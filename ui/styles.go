package ui

import "github.com/charmbracelet/lipgloss"

// Palette สีสไตล์ Modern Dark / btop (Cyberpunk / Terminal Chic)
var (
	ColorPrimary   = lipgloss.Color("#7D56F4") // ม่วงสด
	ColorSecondary = lipgloss.Color("#04B575") // เขียวสด (Normal/OK)
	ColorCyan      = lipgloss.Color("#00E5FF") // ฟ้า Neon
	ColorWarning   = lipgloss.Color("#FFAF00") // เหลือง/ส้ม (Medium Alert)
	ColorDanger    = lipgloss.Color("#FF3366") // แดงนีออน (High/Critical)
	ColorMuted     = lipgloss.Color("#626262") // เทาเข้ม
	ColorDarkBg    = lipgloss.Color("#1A1A24") // พื้นหลังเข้ม
	ColorHighlight = lipgloss.Color("#2A2A38") // แถบเลือก Highlight
	ColorWhite     = lipgloss.Color("#FFFFFF")
)

// สไตล์ของกรอบและหน้าต่าง (Panes)
var (
	// Header Box
	HeaderStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(ColorPrimary).
			Padding(0, 1)

	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorCyan)

	MetricLabelStyle = lipgloss.NewStyle().
				Foreground(ColorMuted)

	MetricValNormal = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorSecondary)

	MetricValWarn = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorWarning)

	MetricValDanger = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorDanger)

	// ตาราง Event
	TableBoxStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(ColorMuted)

	TableBoxFocused = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(ColorCyan)

	TableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorCyan).
				Background(ColorDarkBg)

	RowNormal = lipgloss.NewStyle().
			Foreground(ColorWhite)

	RowSelected = lipgloss.NewStyle().
			Background(ColorHighlight).
			Bold(true)

	// Tag สถานะต่างๆ
	TagNormal = lipgloss.NewStyle().
			Foreground(ColorSecondary).
			SetString("NORMAL")

	TagHandshakeOK = lipgloss.NewStyle().
			Foreground(ColorCyan).
			SetString("ESTABLISHED")

	TagRetrans = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorDanger).
			SetString("RETRANSMIT")

	TagLatencyAlert = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorWarning).
			SetString("HIGH LATENCY")

	TagSYNFlood = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorDanger).
			Blink(true).
			SetString("SYN FLOOD")

	TagIncomplete = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorWarning).
			SetString("INCOMPLETE")

	// กล่องข้อความด้านล่าง (Detail / Help Bar)
	FooterStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(ColorMuted).
			Padding(0, 1)

	KeyBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorDarkBg).
			Background(ColorPrimary).
			Padding(0, 1)

	HelpText = lipgloss.NewStyle().
			Foreground(ColorMuted)
)
