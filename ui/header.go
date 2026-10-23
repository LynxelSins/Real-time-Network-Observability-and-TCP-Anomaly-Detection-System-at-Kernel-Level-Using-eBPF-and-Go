package ui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

// renderHeader วาดแถบสรุปข้อมูลสถิติด้านบนของจอ
func (m Model) renderHeader(availWidth int) string {
	title := TitleStyle.Render("⚡ eBPF TCP Anomaly Monitor")

	// โหมดการตรวจจับ
	modeStr := MetricValNormal.Render(m.stats.DetectionMode)
	if m.stats.DetectionMode == "ADAPTIVE" {
		modeStr = MetricValWarn.Render("ADAPTIVE (μ+3σ)")
	}

	// สถานะ Drops
	var dropStr string
	totalDrops := m.stats.KernelStateDrops + m.stats.KernelRetransDrops
	if totalDrops > 0 {
		dropStr = MetricValDanger.Render(fmt.Sprintf("%d DROPS", totalDrops))
	} else {
		dropStr = MetricValNormal.Render("0 drops")
	}

	// บรรทัดที่ 1: ชื่อโปรแกรม + Mode + Drops
	line1Left := fmt.Sprintf("%s  │  Mode: %s", title, modeStr)
	line1Right := fmt.Sprintf("RingBuf: %s", dropStr)

	gap1 := availWidth - lipgloss.Width(line1Left) - lipgloss.Width(line1Right) - 4
	if gap1 < 1 {
		gap1 = 1
	}
	line1 := fmt.Sprintf("%s%*s%s", line1Left, gap1, "", line1Right)

	// บรรทัดที่ 2: สถิติ Metrics
	statsLine := fmt.Sprintf(
		"Events: %s  │  States: %s  │  Retrans: %s  │  Anomalies: %s  │  μ: %.1fms σ: %.1fms Thresh: %.1fms",
		MetricValNormal.Render(fmt.Sprintf("%d", m.stats.TotalEvents)),
		MetricLabelStyle.Render(fmt.Sprintf("%d", m.stats.StateEvents)),
		formatRetrans(m.stats.RetransEvents),
		formatAnomalies(m.stats.AnomaliesCount),
		m.stats.AdaptiveMean,
		m.stats.AdaptiveStdDev,
		m.stats.AdaptiveThreshold,
	)

	content := lipgloss.JoinVertical(lipgloss.Left, line1, statsLine)
	return HeaderStyle.Width(availWidth - 2).Render(content)
}

func formatRetrans(cnt uint64) string {
	if cnt > 0 {
		return MetricValWarn.Render(fmt.Sprintf("%d", cnt))
	}
	return MetricValNormal.Render("0")
}

func formatAnomalies(cnt uint64) string {
	if cnt > 0 {
		return MetricValDanger.Render(fmt.Sprintf("%d", cnt))
	}
	return MetricValNormal.Render("0")
}
