package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ProcessedEvent ข้อมูล Event ที่ผ่านการวิเคราะห์โดย Detector แล้ว
type ProcessedEvent struct {
	Event     *TCPEvent       `json:"event"`
	Detection DetectionResult `json:"detection"`
}

// EventDispatcher จัดการกระจาย Event ไปยัง TUI / Subscribers และบันทึกลงไฟล์ JSON
type EventDispatcher struct {
	mu           sync.Mutex
	logFile      *os.File
	encoder      *json.Encoder
	subscribers  []chan ProcessedEvent
	droppedAlert uint64
}

// NewEventDispatcher สร้าง Dispatcher พร้อมเปิดไฟล์สำหรับบันทึก Log
func NewEventDispatcher(logPath string) (*EventDispatcher, error) {
	var file *os.File
	var enc *json.Encoder

	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file %s: %w", logPath, err)
		}
		file = f
		enc = json.NewEncoder(f)
	}

	return &EventDispatcher{
		logFile:     file,
		encoder:     enc,
		subscribers: make([]chan ProcessedEvent, 0),
	}, nil
}

// Subscribe ลงทะเบียนรับ Stream ของ Event (เช่น นำไปแสดงผลบน TUI)
// bufferSize กำหนดขนาด channel หากผู้รับอ่านไม่ทัน Event เก่าจะไม่บล็อก Kernel reader
func (d *EventDispatcher) Subscribe(bufferSize int) <-chan ProcessedEvent {
	d.mu.Lock()
	defer d.mu.Unlock()

	ch := make(chan ProcessedEvent, bufferSize)
	d.subscribers = append(d.subscribers, ch)
	return ch
}

// Dispatch ส่งต่อ Event ที่วิเคราะห์แล้วไปยังทุก subscriber และบันทึกลงไฟล์
func (d *EventDispatcher) Dispatch(pe ProcessedEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 1. บันทึกลงไฟล์ JSONL (ถ้าเปิดไฟล์ไว้ และเป็น Anomaly)
	if d.encoder != nil && pe.Detection.IsAnomaly {
		// สร้างโครงสร้าง Log ที่อ่านง่ายสำหรับนำไปทำ Data Analysis
		logRecord := map[string]interface{}{
			"timestamp":     pe.Event.Timestamp.Format(time.RFC3339Nano),
			"anomaly_type":  pe.Detection.Type,
			"severity":      pe.Detection.Severity,
			"src":           fmt.Sprintf("%s:%d", pe.Event.SrcIP, pe.Event.SrcPort),
			"dst":           fmt.Sprintf("%s:%d", pe.Event.DstIP, pe.Event.DstPort),
			"process":       pe.Event.Process,
			"state_change":  fmt.Sprintf("%s->%s", pe.Event.OldStateName, pe.Event.NewStateName),
			"duration_ms":   float64(pe.Event.Duration.Nanoseconds()) / 1_000_000.0,
			"score":         pe.Detection.Score,
			"threshold":     pe.Detection.Threshold,
			"description":   pe.Detection.Description,
		}
		_ = d.encoder.Encode(logRecord)
	}

	// 2. กระจาย Event ให้ Subscribers แบบ Non-blocking (TUI / Monitors)
	for _, ch := range d.subscribers {
		select {
		case ch <- pe:
		default:
			// Subscriber ทำงานไม่ทัน ข้ามเพื่อป้องกัน eBPF reader กระตุก
			d.droppedAlert++
		}
	}
}

// Close ปิดไฟล์ Log และ Channel ทั้งหมด
func (d *EventDispatcher) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, ch := range d.subscribers {
		close(ch)
	}
	d.subscribers = nil

	if d.logFile != nil {
		return d.logFile.Close()
	}
	return nil
}
