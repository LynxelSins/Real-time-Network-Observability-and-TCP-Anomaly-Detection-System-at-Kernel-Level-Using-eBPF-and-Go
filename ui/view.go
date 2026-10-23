package ui

import (
	"github.com/charmbracelet/lipgloss"
)

// View ประกอบทุก Component (Header + Table + Footer) รวมเป็นหน้าจอ Dashboard เดียว
func (m Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Starting eBPF TCP Monitor TUI..."
	}

	w := m.width
	h := m.height

	// 1. Header (ความสูงประมาณ 4 บรรทัด รวมขอบ)
	headerView := m.renderHeader(w)
	headerHeight := lipgloss.Height(headerView)

	// 2. Footer (ความสูงประมาณ 4 บรรทัด รวมขอบ)
	footerView := m.renderFooter(w)
	footerHeight := lipgloss.Height(footerView)

	// 3. Table พื้นที่ที่เหลือตรงกลาง
	tableHeight := h - headerHeight - footerHeight - 1
	if tableHeight < 3 {
		tableHeight = 3
	}
	tableView := m.renderTable(w, tableHeight)

	return lipgloss.JoinVertical(lipgloss.Left, headerView, tableView, footerView)
}
