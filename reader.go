package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// TCPEvent คือโครงสร้าง Event ที่ User Space ใช้งาน
type TCPEvent struct {
	Timestamp    time.Time
	Duration     time.Duration
	SrcIP        string
	DstIP        string
	SrcPort      uint16
	DstPort      uint16
	Process      string
	OldState     uint8
	NewState     uint8
	OldStateName string
	NewStateName string
	EventType    uint8
	IsIncomplete bool
}

// BPFStats บันทึกสถิติการรับ Event และ Drop
type BPFStats struct {
	TotalEvents        uint64
	StateChangeEvents  uint64
	RetransmitEvents   uint64
	KernelStateDrops   uint64
	KernelRetransDrops uint64
}

// EventReader จัดการการอ่านข้อมูลจาก eBPF Ring Buffer และ BPF Maps
type EventReader struct {
	rd           *ringbuf.Reader
	dropCounters *ebpf.Map
	stats        BPFStats
}

// NewEventReader สร้างตัวอ่าน Ring Buffer พร้อม Map สำหรับอ่าน Kernel Drop Counter
func NewEventReader(eventsMap *ebpf.Map, dropCountersMap *ebpf.Map) (*EventReader, error) {
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, fmt.Errorf("failed to open ringbuf reader: %w", err)
	}

	return &EventReader{
		rd:           rd,
		dropCounters: dropCountersMap,
	}, nil
}

// Close ปิดตัวอ่าน Ring Buffer
func (r *EventReader) Close() error {
	return r.rd.Close()
}

// ReadEvent อ่านและแปลง Raw Byte จาก Kernel เป็น TCPEvent
func (r *EventReader) ReadEvent() (*TCPEvent, error) {
	record, err := r.rd.Read()
	if err != nil {
		return nil, err
	}

	var raw bpfTcpEvent
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
		return nil, fmt.Errorf("failed to decode bpfTcpEvent: %w", err)
	}

	atomic.AddUint64(&r.stats.TotalEvents, 1)

	event := &TCPEvent{
		Timestamp:    time.Now(),
		Duration:     time.Duration(raw.DurationNs) * time.Nanosecond,
		SrcIP:        net.IP(raw.Saddr[:]).String(),
		DstIP:        net.IP(raw.Daddr[:]).String(),
		SrcPort:      raw.Sport,
		DstPort:      raw.Dport,
		Process:      formatComm(raw.Comm[:]),
		OldState:     raw.Oldstate,
		NewState:     raw.Newstate,
		OldStateName: getTCPStateName(raw.Oldstate),
		NewStateName: getTCPStateName(raw.Newstate),
		EventType:    raw.EventType,
	}

	if raw.EventType == EventTypeRetransmit {
		atomic.AddUint64(&r.stats.RetransmitEvents, 1)
	} else {
		atomic.AddUint64(&r.stats.StateChangeEvents, 1)
		// ตรวจสอบว่าเป็นการปิด connection ก่อนที่จะ Handshake สำเร็จหรือไม่
		if (raw.Oldstate == 2 /* SYN_SENT */ || raw.Oldstate == 3 /* SYN_RECV */) && raw.Newstate == 7 /* CLOSE */ {
			event.IsIncomplete = true
		}
	}

	return event, nil
}

// ReadStats อ่านสถิติปัจจุบัน ทั้งจาก User Space counters และ Kernel BPF Map
func (r *EventReader) ReadStats() BPFStats {
	current := BPFStats{
		TotalEvents:       atomic.LoadUint64(&r.stats.TotalEvents),
		StateChangeEvents: atomic.LoadUint64(&r.stats.StateChangeEvents),
		RetransmitEvents:  atomic.LoadUint64(&r.stats.RetransmitEvents),
	}

	if r.dropCounters != nil {
		var idx0 uint32 = 0
		var kDrops0 uint64
		if err := r.dropCounters.Lookup(&idx0, &kDrops0); err == nil {
			current.KernelStateDrops = kDrops0
		}

		var idx1 uint32 = 1
		var kDrops1 uint64
		if err := r.dropCounters.Lookup(&idx1, &kDrops1); err == nil {
			current.KernelRetransDrops = kDrops1
		}
	}

	return current
}

func formatComm(comm []int8) string {
	var b strings.Builder
	for _, c := range comm {
		if c == 0 {
			break
		}
		b.WriteByte(byte(c))
	}
	s := b.String()
	if s == "" {
		return "unknown"
	}
	return s
}
