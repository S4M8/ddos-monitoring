package main

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Model represents the TUI model
type model struct {
	monitor *NetworkMonitor
	width   int
	height  int
}

// NewModel creates a new model
func NewModel(monitor *NetworkMonitor) tea.Model {
	return model{
		monitor: monitor,
	}
}

// Init initializes the model
func (m model) Init() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Update handles messages and updates the model
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tickMsg:
		return m, tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return tickMsg(t)
		})
	}
	return m, nil
}

// View renders the UI
func (m model) View() string {
	s := "DDoS Monitoring Dashboard\n\n"

	stats := m.monitor.metrics.GetAll()

	// Active Connections
	activeConnections := stats["ddos_active_connections"]
	s += fmt.Sprintf("Active Connections: %v\n", activeConnections)

	// Suspicious Traffic
	suspiciousCount := stats["ddos_suspicious_count"]
	s += fmt.Sprintf("Suspicious Traffic: %v\n", suspiciousCount)

	// Packets per second
	ppsStats := stats["ddos_packets_per_second"]
	s += fmt.Sprintf("Packets per Second (PPS):\n")
	if ppsMap, ok := ppsStats.(map[string]float64); ok {
		for ip, pps := range ppsMap {
			s += fmt.Sprintf("  %s: %.2f\n", ip, pps)
		}
	}

	// Bytes per second
    bps := stats["ddos_bytes_per_second"]
    s += fmt.Sprintf("Bytes per Second (BPS): %v\n", bps)

	// Suspicious IPs
	suspiciousIPs := stats["ddos_suspicious_ips"]
	s += fmt.Sprintf("Suspicious IPs:\n")
	if ipMap, ok := suspiciousIPs.(map[string]int64); ok {
		for ip, status := range ipMap {
			if status == 1 {
				s += fmt.Sprintf("  %s (Suspicious)\n", ip)
			}
		}
	}

	// Style the output
	style := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("63")).
		Padding(1, 2).
		Width(m.width - 4).
		Height(m.height - 4)

	return style.Render(s)
}

type tickMsg time.Time