package main

/*
 * main.go
 *
 * ส่วน User Space (Go Application) สำหรับดึงข้อมูลจาก eBPF Ring Buffer
 * และทำ Threshold-based Anomaly Detection
 *
 * โฟลวการทำงาน:
 * 1. ปลดล็อกข้อจำกัดหน่วยความจำ (RLIMIT_MEMLOCK) ของเคอร์เนล
 * 2. โหลด eBPF Bytecode เข้าสู่ Kernel และเชื่อมต่อ (Attach) เข้ากับ Tracepoints
 * 3. เปิดตัวอ่าน Ring Buffer (ringbuf.Reader)
 * 4. วนลูปอ่าน Event ที่ถูกส่งมาจากเคอร์เนลแบบ Real-time
 * 5. ถอดรหัส Struct และคำนวณ Feature เพื่อเปรียบเทียบกับ Threshold หาความผิดปกติ
 */

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
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

// กำหนดเกณฑ์ Threshold สำหรับการตรวจจับความผิดปกติ (Toy Model Baseline)
const (
	// Handshake Latency เกิน 50 มิลลิวินาที ถือว่าเริ่มช้าผิดปกติ
	ThresholdHandshakeLatencyMs = 50.0
	// ประเภท Event จาก eBPF C
	EventTypeStateChange = 1
	EventTypeRetransmit  = 2
)

// ANSI Color Codes สำหรับแต่งสี Output บน Terminal ให้อ่านง่าย
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

func main() {
	// -------------------------------------------------------------
	// 1. ดักจับ Signal (Ctrl+C หรือ SIGTERM) เพื่อปิดโปรแกรมอย่างปลอดภัย (Graceful Shutdown)
	// -------------------------------------------------------------
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	fmt.Println(colorBold + colorCyan + "==========================================================" + colorReset)
	fmt.Println(colorBold + colorCyan + "  eBPF TCP Network Monitor & Anomaly Detector (Toy Model) " + colorReset)
	fmt.Println(colorBold + colorCyan + "==========================================================" + colorReset)
	fmt.Println("🚀 กำลังเริ่มต้นโหลด eBPF โปรแกรมเข้าสู่ Kernel...")

	// -------------------------------------------------------------
	// 2. ปลดล็อก Memory Limit (rlimit)
	// Kernel ยุคเก่าจะจำกัดหน่วยความจำที่ BPF Map ใช้ได้ คำสั่งนี้ช่วยปลดล็อกให้ทำงานได้ราบรื่น
	// -------------------------------------------------------------
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("ล้มเหลวในการปลดล็อก rlimit memlock: %v", err)
	}

	// -------------------------------------------------------------
	// 3. โหลด BPF Objects (Programs & Maps) ที่ถูก generate มาจาก bpf2go
	// -------------------------------------------------------------
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("ล้มเหลวในการโหลด BPF objects (ต้องรันด้วย sudo หรือมีสิทธิ์ root): %v", err)
	}
	defer objs.Close()

	// -------------------------------------------------------------
	// 4. ติดตั้ง (Attach) eBPF Program เข้ากับ Kernel Tracepoints
	// -------------------------------------------------------------
	// 4.1 Tracepoint: sock/inet_sock_set_state (ดักจับการเปลี่ยนสถานะ TCP)
	tpState, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TraceInetSockSetState, nil)
	if err != nil {
		log.Fatalf("ล้มเหลวในการแนบ Tracepoint inet_sock_set_state: %v", err)
	}
	defer tpState.Close()

	// 4.2 Tracepoint: tcp/tcp_retransmit_skb (ดักจับการส่งข้อมูลซ้ำ)
	tpRetransmit, err := link.Tracepoint("tcp", "tcp_retransmit_skb", objs.TraceTcpRetransmit, nil)
	if err != nil {
		log.Fatalf("ล้มเหลวในการแนบ Tracepoint tcp_retransmit_skb: %v", err)
	}
	defer tpRetransmit.Close()

	// -------------------------------------------------------------
	// 5. เปิดตัวอ่าน Ring Buffer จาก BPF Map ที่ชื่อ 'events'
	// -------------------------------------------------------------
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ล้มเหลวในการเปิด RingBuffer reader: %v", err)
	}
	defer rd.Close()

	// Goroutine สำหรับปิด RingBuffer เมื่อผู้ใช้กด Ctrl+C
	go func() {
		<-stopper
		fmt.Println("\n🛑 ได้รับคำสั่งหยุดการทำงาน กำลังออกจากโปรแกรมและถอด eBPF...")
		if err := rd.Close(); err != nil {
			log.Fatalf("ปิด ringbuf reader ล้มเหลว: %v", err)
		}
	}()

	fmt.Println(colorGreen + "✔ ติดตั้ง eBPF Tracepoints สำเร็จ พร้อมรับ Events จาก Kernel แล้ว!" + colorReset)
	fmt.Printf("📊 เกณฑ์แจ้งเตือน (Thresholds): Handshake Latency > %.1f ms | Retransmission > 0\n", ThresholdHandshakeLatencyMs)
	fmt.Println("------------------------------------------------------------------------------------------------------------------------")
	fmt.Printf("%-10s %-16s %-21s %-21s %-16s %-12s %s\n",
		"TIME", "PROCESS", "SRC ADDR", "DST ADDR", "STATE TRANSITION", "DURATION", "STATUS/ALERT")
	fmt.Println("------------------------------------------------------------------------------------------------------------------------")

	// -------------------------------------------------------------
	// 6. วนลูปอ่านข้อมูล Event จาก Ring Buffer (Event-driven)
	// -------------------------------------------------------------
	var event bpfTcpEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				// โปรแกรมถูกสั่งปิด
				break
			}
			log.Printf("เกิดข้อผิดพลาดในการอ่าน RingBuffer: %v", err)
			continue
		}

		// ถอดรหัสไบนารีข้อมูลที่ Kernel ส่งมา แปลงลง struct bpfTcpEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("ถอดรหัส Event ล้มเหลว: %v", err)
			continue
		}

		// นำ Event ไปวิเคราะห์และแสดงผล
		processEvent(&event)
	}

	fmt.Println("ระบบปิดการทำงานเรียบร้อยแล้ว!")
}

/*
 * processEvent: ทำหน้าที่ดึงข้อมูล (Feature Extraction) และตรวจสอบความผิดปกติ (Threshold Anomaly Detection)
 */
func processEvent(event *bpfTcpEvent) {
	// แปลง IP Address และ Port
	srcIP := net.IP(event.Saddr[:]).String()
	dstIP := net.IP(event.Daddr[:]).String()
	src := fmt.Sprintf("%s:%d", srcIP, event.Sport)
	dst := fmt.Sprintf("%s:%d", dstIP, event.Dport)

	// แปลงชื่อ Process (Task comm)
	comm := int8ArrayToString(event.Comm[:])
	if comm == "" {
		comm = "unknown"
	}

	currentTime := time.Now().Format("15:04:05")

	// กรณีที่ 1: ตรวจพบ TCP Retransmission (การส่งแพ็กเก็ตซ้ำ)
	if event.EventType == EventTypeRetransmit {
		alertMsg := fmt.Sprintf("%s[ANOMALY: RETRANSMISSION]%s", colorRed+colorBold, colorReset)
		fmt.Printf("%-10s %-16s %-21s %-21s %-16s %-12s %s\n",
			currentTime, comm, src, dst, "RETRANSMIT", "-", alertMsg)
		return
	}

	// กรณีที่ 2: มีการเปลี่ยนแปลงสถานะ (State Change)
	oldStateStr := getTCPStateName(event.Oldstate)
	newStateStr := getTCPStateName(event.Newstate)
	transition := fmt.Sprintf("%s->%s", oldStateStr, newStateStr)

	durationMs := float64(event.DurationNs) / 1_000_000.0 // แปลงนาโนวินาทีเป็นมิลลิวินาที

	durationStr := "-"
	statusMsg := fmt.Sprintf("%s[NORMAL]%s", colorGreen, colorReset)

	// ตรวจจับ Handshake Latency เมื่อ Socket เปลี่ยนเป็น ESTABLISHED
	if event.Newstate == 1 /* TCP_ESTABLISHED */ && event.DurationNs > 0 {
		durationStr = fmt.Sprintf("%.2f ms", durationMs)

		// ตรวจสอบ Threshold ว่า Handshake ใช้เวลานานเกินกำหนดหรือไม่
		if durationMs > ThresholdHandshakeLatencyMs {
			statusMsg = fmt.Sprintf("%s[ANOMALY: HIGH LATENCY (%.1fms)]%s", colorRed+colorBold, durationMs, colorReset)
		} else {
			statusMsg = fmt.Sprintf("%s[HANDSHAKE OK]%s", colorCyan, colorReset)
		}
	} else if event.Newstate == 7 /* TCP_CLOSE */ && event.DurationNs > 0 {
		// Connection จบลง บันทึกเวลาที่เชื่อมต่อทั้งหมด
		durationStr = fmt.Sprintf("%.2f s", durationMs/1000.0)
		statusMsg = fmt.Sprintf("%s[CLOSED]%s", colorYellow, colorReset)
	}

	// แสดงผลออกทางหน้าจอ Console
	fmt.Printf("%-10s %-16s %-21s %-21s %-16s %-12s %s\n",
		currentTime, comm, src, dst, transition, durationStr, statusMsg)
}

// แปลงค่า Integer State เป็นข้อความภาษาอังกฤษ
func getTCPStateName(state uint8) string {
	if name, ok := tcpStateNames[state]; ok {
		return name
	}
	return fmt.Sprintf("STATE_%d", state)
}

// แปลง Array ของ int8 (C char array) เป็น Go string
func int8ArrayToString(arr []int8) string {
	var b strings.Builder
	for _, c := range arr {
		if c == 0 {
			break
		}
		b.WriteByte(byte(c))
	}
	return b.String()
}
