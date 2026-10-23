package ui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// UIEvent ตัวแทนของ Event ที่นำมาแสดงผลบนตาราง
type UIEvent struct {
	Timestamp   time.Time
	Process     string
	Src         string
	Dst         string
	Transition  string
	DurationStr string
	DurationMs  float64
	IsAnomaly   bool
	AnomalyType string
	Severity    string
	Description string
}

// StatsSnapshot ภาพรวมสถิติส่งมาให้ UI เรนเดอร์
type StatsSnapshot struct {
	TotalEvents        uint64
	StateEvents        uint64
	RetransEvents      uint64
	AnomaliesCount     uint64
	KernelStateDrops   uint64
	KernelRetransDrops uint64
	DetectionMode      string
	AdaptiveMean       float64
	AdaptiveStdDev     float64
	AdaptiveThreshold  float64
}

// Bubble Tea Message Types
type EventMsg UIEvent
type StatsMsg StatsSnapshot
type TickMsg time.Time

// FocusPane สถานะว่าผู้ใช้กำลังโฟกัสที่หน้าต่างไหน
type FocusPane int

const (
	FocusTable FocusPane = iota
	FocusAlerts
)

// Model โครงสร้างข้อมูลหลักตาม Elm Architecture ของ Bubbletea
type Model struct {
	width  int
	height int

	// Event Streams
	eventChan <-chan UIEvent
	statsFunc func() StatsSnapshot

	// UI State
	events     []UIEvent
	maxEvents  int
	selected   int
	paused     bool
	focus      FocusPane
	filterType string // "" (ทั้งหมด), "ANOMALY", "RETRANS", etc.

	// Statistics
	stats StatsSnapshot
}

// NewModel สร้าง Model เริ่มต้น
func NewModel(eventChan <-chan UIEvent, statsFunc func() StatsSnapshot) Model {
	return Model{
		eventChan:  eventChan,
		statsFunc:  statsFunc,
		events:     make([]UIEvent, 0, 100),
		maxEvents:  500,
		selected:   0,
		paused:     false,
		focus:      FocusTable,
		filterType: "",
	}
}

// waitForEvent สั่งให้ Bubbletea รอรับ Event ถัดไปจาก Channel
func waitForEvent(sub <-chan UIEvent) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-sub
		if !ok {
			return nil
		}
		return EventMsg(ev)
	}
}

// tickEvery สั่งให้ส่ง TickMsg ทุกๆ Interval เพื่ออัปเดตสถิติ
func tickEvery(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

// Init กำหนดการทำงานเริ่มต้นของ Bubbletea
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		waitForEvent(m.eventChan),
		tickEvery(250*time.Millisecond), // รีเฟรชสถิติทุก 250ms
	)
}

// Update จัดการเหตุการณ์ต่างๆ เช่น ปุ่มคีย์บอร์ด, Event เข้ามา, Tick เวลา
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit

		case " ":
			m.paused = !m.paused

		case "tab":
			if m.focus == FocusTable {
				m.focus = FocusAlerts
			} else {
				m.focus = FocusTable
			}

		case "up", "k":
			if m.selected > 0 {
				m.selected--
			}

		case "down", "j":
			if m.selected < len(m.events)-1 {
				m.selected++
			}

		case "home", "g":
			m.selected = 0

		case "end", "G":
			if len(m.events) > 0 {
				m.selected = len(m.events) - 1
			}

		case "c":
			m.events = m.events[:0]
			m.selected = 0
		}

	case EventMsg:
		if !m.paused {
			// แทรก Event ใหม่ไว้บนสุด (newest first สไตล์ dashboard.c)
			ev := UIEvent(msg)
			m.events = append([]UIEvent{ev}, m.events...)
			if len(m.events) > m.maxEvents {
				m.events = m.events[:m.maxEvents]
			}
		}
		// สั่งรอรับ Event ถัดไปต่อทันที
		cmds = append(cmds, waitForEvent(m.eventChan))

	case TickMsg:
		if m.statsFunc != nil {
			m.stats = m.statsFunc()
		}
		cmds = append(cmds, tickEvery(250*time.Millisecond))
	}

	return m, tea.Batch(cmds...)
}
