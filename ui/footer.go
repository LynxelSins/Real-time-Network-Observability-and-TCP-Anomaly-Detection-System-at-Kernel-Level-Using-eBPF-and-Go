package ui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

// renderFooter วาดส่วนแสดงรายละเอียดของ Event ที่เลือก และปุ่ม Help Bar
func (m Model) renderFooter(availWidth int) string {
	var detailText string

	if len(m.events) > 0 && m.selected < len(m.events) {
		ev := m.events[m.selected]
		statusLabel := "NORMAL"
		if ev.IsAnomaly {
			statusLabel = fmt.Sprintf("ANOMALY [%s - %s]", ev.Severity, ev.AnomalyType)
		}

		detailText = fmt.Sprintf(
			"🔎 Selected: %s:%s | %s ➔ %s (%s) | %s\n   Desc: %s",
			ev.Process, ev.Transition, ev.Src, ev.Dst, ev.DurationStr, statusLabel, ev.Description,
		)
	} else {
		detailText = "No events selected."
	}

	// แถบปุ่มลัด (Hotkeys Bar)
	pauseStatus := "Pause"
	if m.paused {
		pauseStatus = MetricValDanger.Render("RESUME")
	}

	keys := fmt.Sprintf(
		"%s quit  %s %s  %s select  %s clear  %s toggle pane",
		KeyBadge.Render("q"),
		KeyBadge.Render("Space"), pauseStatus,
		KeyBadge.Render("↑/↓"),
		KeyBadge.Render("c"),
		KeyBadge.Render("Tab"),
	)

	content := lipgloss.JoinVertical(lipgloss.Left, detailText, HelpText.Render(keys))
	return FooterStyle.Width(availWidth - 2).Render(content)
}
