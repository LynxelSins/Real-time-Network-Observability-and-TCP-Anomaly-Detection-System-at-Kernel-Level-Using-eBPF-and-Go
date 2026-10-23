package main

/*
 * main.go
 *
 * ส่วน User Space (Go Application) สำหรับดึงข้อมูลจาก eBPF Ring Buffer
 * เชื่อมต่อกับ Detection Engine, Structured Logger และ TUI Dashboard
 */

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"ebpf-tcp-monitor/ui"
)

// นิยามชื่อสถานะของ TCP ตามมาตรฐาน Linux Kernel
var tcpStateNames = map[uint8]string{
	1:  "ESTABLISHED",
	2:  "SYN_SENT",
	3:  "SYN_RECV",
	4:  "FIN_WAIT1",
	5:  "FIN_WAIT2",
	6:  "TIME_WAIT",
	7:  "CLOSE",
	8:  "CLOSE_WAIT",
	9:  "LAST_ACK",
	10: "LISTEN",
	11: "CLOSING",
	12: "NEW_SYN_RECV",
}

const (
	EventTypeStateChange = 1
	EventTypeRetransmit  = 2
)

// ANSI Color Codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

func main() {
	// รับ Command-line Flags
	useTUI := flag.Bool("tui", true, "เปิดการแสดงผลแบบ TUI Dashboard (bubbletea)")
	modeFlag := flag.String("mode", "static", "โหมดตรวจจับ: 'static' หรือ 'adaptive'")
	logFile := flag.String("log", "alerts.jsonl", "ไฟล์บันทึกประวัติ Anomaly Alerts (JSONL)")
	threshFlag := flag.Float64("threshold", 50.0, "ค่า Latency Threshold (ms) สำหรับโหมด static")
	flag.Parse()

	// 1. ปลดล็อก Memory Limit (rlimit)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("ล้มเหลวในการปลดล็อก rlimit memlock: %v", err)
	}

	// 2. โหลด BPF Objects
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("ล้มเหลวในการโหลด BPF objects (ต้องรันด้วย sudo หรือสิทธิ์ root): %v", err)
	}
	defer objs.Close()

	// 3. แนบ Kernel Tracepoints
	tpState, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TraceInetSockSetState, nil)
	if err != nil {
		log.Fatalf("ล้มเหลวในการแนบ Tracepoint inet_sock_set_state: %v", err)
	}
	defer tpState.Close()

	tpRetransmit, err := link.Tracepoint("tcp", "tcp_retransmit_skb", objs.TraceTcpRetransmit, nil)
	if err != nil {
		log.Fatalf("ล้มเหลวในการแนบ Tracepoint tcp_retransmit_skb: %v", err)
	}
	defer tpRetransmit.Close()

	// 4. สร้าง EventReader (Ring Buffer)
	reader, err := NewEventReader(objs.Events, objs.DropCounters)
	if err != nil {
		log.Fatalf("ล้มเหลวในการเปิด EventReader: %v", err)
	}
	defer reader.Close()

	// 5. ตั้งค่า Detection Engine & Logger Dispatcher
	detCfg := DefaultDetectorConfig()
	detCfg.StaticLatencyThresholdMs = *threshFlag
	if *modeFlag == "adaptive" {
		detCfg.Mode = ModeAdaptive
	}
	detector := NewAnomalyDetector(detCfg)

	dispatcher, err := NewEventDispatcher(*logFile)
	if err != nil {
		log.Fatalf("ล้มเหลวในการสร้าง Dispatcher: %v", err)
	}
	defer dispatcher.Close()

	// ช่องทางส่ง Event ขึ้น TUI
	uiEventChan := make(chan ui.UIEvent, 200)
	var anomalyCount uint64

	// สถิติ Snapshot ส่งให้ UI
	statsFunc := func() ui.StatsSnapshot {
		bpfStats := reader.ReadStats()
		mean, stdDev, _ := detector.GetStats()
		var curThresh float64
		if detector.GetMode() == ModeAdaptive {
			curThresh = mean + (3.0 * stdDev)
		} else {
			curThresh = detCfg.StaticLatencyThresholdMs
		}

		return ui.StatsSnapshot{
			TotalEvents:        bpfStats.TotalEvents,
			StateEvents:        bpfStats.StateChangeEvents,
			RetransEvents:      bpfStats.RetransmitEvents,
			AnomaliesCount:     atomic.LoadUint64(&anomalyCount),
			KernelStateDrops:   bpfStats.KernelStateDrops,
			KernelRetransDrops: bpfStats.KernelRetransDrops,
			DetectionMode:      string(detector.GetMode()),
			AdaptiveMean:       mean,
			AdaptiveStdDev:     stdDev,
			AdaptiveThreshold:  curThresh,
		}
	}

	// 6. Background Goroutine: วนลูปอ่าน eBPF Event และประมวลผล
	go func() {
		for {
			event, err := reader.ReadEvent()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					break
				}
				continue
			}

			// วิเคราะห์ Event ผ่าน Detector
			detResult := detector.Analyze(event)
			if detResult.IsAnomaly {
				atomic.AddUint64(&anomalyCount, 1)
			}

			// ส่งต่อเข้า Dispatcher (บันทึกลง JSONL)
			dispatcher.Dispatch(ProcessedEvent{
				Event:     event,
				Detection: detResult,
			})

			// แปลงเป็น UIEvent สำหรับ TUI หรือพิมพ์ออก CLI
			durMs := float64(event.Duration.Nanoseconds()) / 1_000_000.0
			durStr := "-"
			if event.Duration > 0 {
				if durMs >= 1000.0 {
					durStr = fmt.Sprintf("%.2fs", durMs/1000.0)
				} else {
					durStr = fmt.Sprintf("%.1fms", durMs)
				}
			}

			uiEv := ui.UIEvent{
				Timestamp:   event.Timestamp,
				Process:     event.Process,
				Src:         fmt.Sprintf("%s:%d", event.SrcIP, event.SrcPort),
				Dst:         fmt.Sprintf("%s:%d", event.DstIP, event.DstPort),
				Transition:  fmt.Sprintf("%s->%s", event.OldStateName, event.NewStateName),
				DurationStr: durStr,
				DurationMs:  durMs,
				IsAnomaly:   detResult.IsAnomaly,
				AnomalyType: string(detResult.Type),
				Severity:    detResult.Severity,
				Description: detResult.Description,
			}

			if *useTUI {
				select {
				case uiEventChan <- uiEv:
				default:
					// TUI รับไม่ทัน ข้ามเพื่อไม่ให้บล็อก
				}
			} else {
				printCLIEvent(uiEv)
			}
		}
	}()

	// 7. การแสดงผล (TUI หรือ CLI Loop)
	if *useTUI {
		model := ui.NewModel(uiEventChan, statsFunc)
		p := tea.NewProgram(model, tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			log.Fatalf("Error running TUI program: %v", err)
		}
	} else {
		// รันในโหมด CLI ปกติ
		stopper := make(chan os.Signal, 1)
		signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
		fmt.Printf("🚀 eBPF Monitor running in CLI mode (Mode: %s). Press Ctrl+C to stop...\n", *modeFlag)
		<-stopper
		fmt.Println("\n🛑 Stopping monitor...")
	}
}

func printCLIEvent(ev ui.UIEvent) {
	tag := "[NORMAL]"
	if ev.IsAnomaly {
		tag = fmt.Sprintf("%s[%s]%s", colorRed+colorBold, ev.AnomalyType, colorReset)
	}
	fmt.Printf("%-10s %-14s %-21s %-21s %-16s %-10s %s\n",
		ev.Timestamp.Format("15:04:05"), ev.Process, ev.Src, ev.Dst, ev.Transition, ev.DurationStr, tag)
}

func getTCPStateName(state uint8) string {
	if name, ok := tcpStateNames[state]; ok {
		return name
	}
	return fmt.Sprintf("STATE_%d", state)
}
