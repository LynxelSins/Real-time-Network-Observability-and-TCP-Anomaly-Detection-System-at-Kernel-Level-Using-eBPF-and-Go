package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// renderTable วาดตารางรายการ Event พร้อมระบบ Scroll และ Highlight
func (m Model) renderTable(availWidth int, availHeight int) string {
	if availHeight < 4 {
		return ""
	}

	// 1. หัวตาราง (Table Header)
	// ความกว้างคอลัมน์มาตรฐาน: TIME(8) PROCESS(12) SRC(21) DST(21) TRANSITION(18) DURATION(10) STATUS(14)
	headerText := fmt.Sprintf(" %-8s %-12s %-21s %-21s %-18s %-10s %s",
		"TIME", "PROCESS", "SRC ADDR", "DST ADDR", "STATE TRANSITION", "LATENCY", "STATUS")

	pad := availWidth - lipgloss.Width(headerText) - 2
	if pad > 0 {
		headerText += strings.Repeat(" ", pad)
	}
	renderedHeader := TableHeaderStyle.Render(headerText)

	// 2. คำนวณขอบเขตแถวที่จะแสดง (Pagination / Visible Rows)
	visibleRows := availHeight - 3 // หัก header, border บน-ล่าง
	if visibleRows < 1 {
		visibleRows = 1
	}

	totalEvents := len(m.events)
	if totalEvents == 0 {
		emptyMsg := RowNormal.Render("  Waiting for network events from eBPF kernel...")
		content := lipgloss.JoinVertical(lipgloss.Left, renderedHeader, emptyMsg)
		return m.wrapTableBox(content, availWidth, availHeight)
	}

	// ควบคุมตำแหน่ง Scroll ตาม selected index
	startIdx := 0
	if m.selected >= visibleRows {
		startIdx = m.selected - visibleRows + 1
	}
	endIdx := startIdx + visibleRows
	if endIdx > totalEvents {
		endIdx = totalEvents
	}

	// 3. วาดแต่ละแถว
	var rows []string
	rows = append(rows, renderedHeader)

	for i := startIdx; i < endIdx; i++ {
		ev := m.events[i]
		isSelected := (i == m.selected)

		tagStr := renderTag(ev)
		timeStr := ev.Timestamp.Format("15:04:05")
		procStr := truncateString(ev.Process, 12)
		srcStr := truncateString(ev.Src, 21)
		dstStr := truncateString(ev.Dst, 21)
		transStr := truncateString(ev.Transition, 18)
		durStr := truncateString(ev.DurationStr, 10)

		rowText := fmt.Sprintf(" %-8s %-12s %-21s %-21s %-18s %-10s %s",
			timeStr, procStr, srcStr, dstStr, transStr, durStr, tagStr)

		rowPad := availWidth - lipgloss.Width(rowText) - 2
		if rowPad > 0 {
			rowText += strings.Repeat(" ", rowPad)
		}

		if isSelected {
			rows = append(rows, RowSelected.Render(rowText))
		} else {
			rows = append(rows, RowNormal.Render(rowText))
		}
	}

	content := lipgloss.JoinVertical(lipgloss.Left, rows...)
	return m.wrapTableBox(content, availWidth, availHeight)
}

func (m Model) wrapTableBox(content string, width int, height int) string {
	box := TableBoxStyle
	if m.focus == FocusTable {
		box = TableBoxFocused
	}
	return box.Width(width - 2).Height(height).Render(content)
}

func renderTag(ev UIEvent) string {
	if !ev.IsAnomaly {
		if ev.DurationMs > 0 {
			return TagHandshakeOK.String()
		}
		return TagNormal.String()
	}

	switch ev.AnomalyType {
	case "RETRANSMISSION":
		return TagRetrans.String()
	case "HIGH_LATENCY":
		return TagLatencyAlert.String()
	case "SYN_FLOOD_SUSPECT":
		return TagSYNFlood.String()
	case "INCOMPLETE_HANDSHAKE":
		return TagIncomplete.String()
	default:
		return MetricValDanger.Render("ANOMALY")
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		if maxLen > 2 {
			return s[:maxLen-2] + ".."
		}
		return s[:maxLen]
	}
	return s
}
