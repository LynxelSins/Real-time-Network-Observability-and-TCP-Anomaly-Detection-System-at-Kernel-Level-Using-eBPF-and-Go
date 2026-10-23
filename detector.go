package main

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// AnomalyType ประเภทของความผิดปกติที่ตรวจพบ
type AnomalyType string

const (
	AnomalyNone               AnomalyType = "NONE"
	AnomalyHighLatency        AnomalyType = "HIGH_LATENCY"
	AnomalyRetransmission     AnomalyType = "RETRANSMISSION"
	AnomalyIncompleteHandshake AnomalyType = "INCOMPLETE_HANDSHAKE"
	AnomalySYNFloodSuspect    AnomalyType = "SYN_FLOOD_SUSPECT"
)

// DetectionMode โหมดการตรวจจับ
type DetectionMode string

const (
	ModeStatic   DetectionMode = "STATIC"
	ModeAdaptive DetectionMode = "ADAPTIVE"
)

// DetectionResult ผลลัพธ์จากการตรวจสอบ Event
type DetectionResult struct {
	IsAnomaly   bool
	Type        AnomalyType
	Severity    string // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Score       float64
	Threshold   float64
	Description string
}

// DetectorConfig ค่าคอนฟิกสำหรับ Detection Engine
type DetectorConfig struct {
	Mode                    DetectionMode
	StaticLatencyThresholdMs float64       // ค่าคงที่ Handshake Latency (ms)
	AdaptiveWindowSize      int           // จำนวน sample ล่าสุดที่ใช้คิด Moving Average
	AdaptiveK               float64       // ตัวคูณ Standard Deviation (เช่น mu + 3*sigma)
	MinSamplesForAdaptive   int           // จำนวน sample ขั้นต่ำก่อนเริ่มใช้ Adaptive
	SYNFloodThresholdPerSec int           // เกณฑ์ Incomplete/SYN ตรวจจับ SYN Flood
}

// DefaultDetectorConfig คืนค่า Config เริ่มต้น
func DefaultDetectorConfig() DetectorConfig {
	return DetectorConfig{
		Mode:                    ModeStatic,
		StaticLatencyThresholdMs: 50.0,
		AdaptiveWindowSize:      50,
		AdaptiveK:               3.0,
		MinSamplesForAdaptive:   10,
		SYNFloodThresholdPerSec: 20,
	}
}

// AnomalyDetector โครงสร้างสำหรับประมวลผลการตรวจจับ
type AnomalyDetector struct {
	mu     sync.RWMutex
	config DetectorConfig

	// สำหรับ Adaptive Latency Tracking (Sliding Window Welford/Buffer)
	latencySamples []float64
	sampleIdx      int
	sampleCount    int
	mean           float64
	stdDev         float64

	// สำหรับตรวจจับ Incomplete Handshake / SYN Flood Rate (ต่อวินาที)
	incompleteTimestamps []time.Time
}

// NewAnomalyDetector สร้าง AnomalyDetector ตัวใหม่
func NewAnomalyDetector(cfg DetectorConfig) *AnomalyDetector {
	return &AnomalyDetector{
		config:               cfg,
		latencySamples:       make([]float64, cfg.AdaptiveWindowSize),
		incompleteTimestamps: make([]time.Time, 0, 100),
	}
}

// SetMode สลับโหมดการตรวจจับ (Static / Adaptive)
func (d *AnomalyDetector) SetMode(mode DetectionMode) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.config.Mode = mode
}

// GetMode คืนค่าโหมดปัจจุบัน
func (d *AnomalyDetector) GetMode() DetectionMode {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.config.Mode
}

// Analyze ตรวจสอบ Event และคืนค่าผลการประเมิน
func (d *AnomalyDetector) Analyze(event *TCPEvent) DetectionResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 1. ตรวจสอบ Retransmission (การส่งข้อมูลซ้ำ)
	if event.EventType == EventTypeRetransmit {
		return DetectionResult{
			IsAnomaly:   true,
			Type:        AnomalyRetransmission,
			Severity:    "HIGH",
			Score:       1.0,
			Threshold:   0.0,
			Description: fmt.Sprintf("TCP Retransmission detected on %s:%d -> %s:%d (%s)", event.SrcIP, event.SrcPort, event.DstIP, event.DstPort, event.Process),
		}
	}

	// 2. ตรวจสอบ Incomplete Handshake / ปิดก่อน ESTABLISHED
	if event.IsIncomplete {
		d.recordIncomplete()
		recentRate := d.countRecentIncompletes(1 * time.Second)

		if recentRate >= d.config.SYNFloodThresholdPerSec {
			return DetectionResult{
				IsAnomaly:   true,
				Type:        AnomalySYNFloodSuspect,
				Severity:    "CRITICAL",
				Score:       float64(recentRate),
				Threshold:   float64(d.config.SYNFloodThresholdPerSec),
				Description: fmt.Sprintf("Suspected SYN Flood! High rate of incomplete handshakes (%d/s)", recentRate),
			}
		}

		return DetectionResult{
			IsAnomaly:   true,
			Type:        AnomalyIncompleteHandshake,
			Severity:    "MEDIUM",
			Score:       1.0,
			Threshold:   0.0,
			Description: fmt.Sprintf("Incomplete Handshake: Socket reset/closed (%s -> %s)", event.OldStateName, event.NewStateName),
		}
	}

	// 3. ตรวจสอบ Handshake Latency เมื่อเชื่อมต่อ ESTABLISHED สำเร็จ
	if event.NewState == 1 /* TCP_ESTABLISHED */ && event.Duration > 0 {
		latencyMs := float64(event.Duration.Nanoseconds()) / 1_000_000.0

		// อัปเดตข้อมูล Adaptive Window
		d.updateLatencyStats(latencyMs)

		var threshold float64
		if d.config.Mode == ModeStatic {
			threshold = d.config.StaticLatencyThresholdMs
			if latencyMs > threshold {
				return DetectionResult{
					IsAnomaly:   true,
					Type:        AnomalyHighLatency,
					Severity:    "MEDIUM",
					Score:       latencyMs,
					Threshold:   threshold,
					Description: fmt.Sprintf("Handshake Latency %.2f ms exceeded static threshold (%.2f ms)", latencyMs, threshold),
				}
			}
		} else {
			// โหมด Adaptive: mu + k * sigma
			if d.sampleCount >= d.config.MinSamplesForAdaptive && d.stdDev > 0 {
				threshold = d.mean + (d.config.AdaptiveK * d.stdDev)
				if latencyMs > threshold {
					return DetectionResult{
						IsAnomaly:   true,
						Type:        AnomalyHighLatency,
						Severity:    "HIGH",
						Score:       latencyMs,
						Threshold:   threshold,
						Description: fmt.Sprintf("Handshake Latency %.2f ms exceeded adaptive threshold (%.2f ms, mean=%.2f, std=%.2f)", latencyMs, threshold, d.mean, d.stdDev),
					}
				}
			} else {
				// ตัวอย่างยังไม่พอ fallback ไปใช้ Static ชั่วคราว
				threshold = d.config.StaticLatencyThresholdMs
				if latencyMs > threshold {
					return DetectionResult{
						IsAnomaly:   true,
						Type:        AnomalyHighLatency,
						Severity:    "LOW",
						Score:       latencyMs,
						Threshold:   threshold,
						Description: fmt.Sprintf("Handshake Latency %.2f ms exceeded initial baseline (%.2f ms)", latencyMs, threshold),
					}
				}
			}
		}
	}

	// ปกติ
	return DetectionResult{
		IsAnomaly:   false,
		Type:        AnomalyNone,
		Severity:    "INFO",
		Score:       0,
		Threshold:   0,
		Description: "Normal TCP Event",
	}
}

// updateLatencyStats คำนวณ mean และ stdDev บน Sliding Window
func (d *AnomalyDetector) updateLatencyStats(latencyMs float64) {
	d.latencySamples[d.sampleIdx] = latencyMs
	d.sampleIdx = (d.sampleIdx + 1) % d.config.AdaptiveWindowSize
	if d.sampleCount < d.config.AdaptiveWindowSize {
		d.sampleCount++
	}

	// คำนวณ Mean
	var sum float64
	for i := 0; i < d.sampleCount; i++ {
		sum += d.latencySamples[i]
	}
	d.mean = sum / float64(d.sampleCount)

	// คำนวณ Standard Deviation
	var varianceSum float64
	for i := 0; i < d.sampleCount; i++ {
		diff := d.latencySamples[i] - d.mean
		varianceSum += diff * diff
	}
	d.stdDev = math.Sqrt(varianceSum / float64(d.sampleCount))
}

// recordIncomplete บันทึก timestamp ของ incomplete connection
func (d *AnomalyDetector) recordIncomplete() {
	now := time.Now()
	d.incompleteTimestamps = append(d.incompleteTimestamps, now)
}

// countRecentIncompletes นับจำนวน incomplete handshakes ในช่วงเวลา window
func (d *AnomalyDetector) countRecentIncompletes(window time.Duration) int {
	cutoff := time.Now().Add(-window)
	validIdx := 0
	for i, ts := range d.incompleteTimestamps {
		if ts.After(cutoff) {
			validIdx = i
			break
		}
	}
	// prune เก่าทิ้ง
	d.incompleteTimestamps = d.incompleteTimestamps[validIdx:]
	return len(d.incompleteTimestamps)
}

// GetStats คืนค่า Mean, StdDev และ Sample Count ปัจจุบัน
func (d *AnomalyDetector) GetStats() (mean float64, stdDev float64, count int) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.mean, d.stdDev, d.sampleCount
}
