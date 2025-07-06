package main

import (
	"fmt"
	"sort"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	tableHeaderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Bold(true)
	rowStyle         = lipgloss.NewStyle().PaddingRight(2)
	suspiciousStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true) // Red color
)

type ipTableRow struct {
	IP         string
	PPS        float64
	BPS        float64
	Protocols  string
	Suspicious bool
}

// Model represents the TUI model
type model struct {
	monitor       *NetworkMonitor
	width         int
	height        int
	ipData        []ipTableRow // Data for the IP table
	recentAlerts  []string     // Stores recent alerts
	sortColumn    string       // Current column being sorted (e.g., "IP", "PPS", "BPS", "Protocols")
	sortAscending bool         // True for ascending, false for descending
}

type alertMsg string

// NewModel creates a new model
func NewModel(monitor *NetworkMonitor) tea.Model {
	return model{
		monitor:       monitor,
		recentAlerts:  make([]string, 0, 5), // Initialize with capacity
		sortColumn:    "PPS",                // Default sort column
		sortAscending: false,                // Default sort order (descending for PPS)
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
		case "1": // Sort by IP
			if m.sortColumn == "IP" {
				m.sortAscending = !m.sortAscending
			} else {
				m.sortColumn = "IP"
				m.sortAscending = true
			}
			m.sortIPData()
		case "2": // Sort by PPS
			if m.sortColumn == "PPS" {
				m.sortAscending = !m.sortAscending
			} else {
				m.sortColumn = "PPS"
				m.sortAscending = false // Default to descending for PPS
			}
			m.sortIPData()
		case "3": // Sort by BPS
			if m.sortColumn == "BPS" {
				m.sortAscending = !m.sortAscending
			} else {
				m.sortColumn = "BPS"
				m.sortAscending = false // Default to descending for BPS
			}
			m.sortIPData()
		case "4": // Sort by Protocols
			if m.sortColumn == "Protocols" {
				m.sortAscending = !m.sortAscending
			} else {
				m.sortColumn = "Protocols"
				m.sortAscending = true
			}
			m.sortIPData()
		case "s": // Sort by Suspicious
			if m.sortColumn == "Suspicious" {
				m.sortAscending = !m.sortAscending
			} else {
				m.sortColumn = "Suspicious"
				m.sortAscending = false // Default to descending (suspicious first)
			}
			m.sortIPData()
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tickMsg:
		// Update IP data for the table
		m.updateIPData()
		return m, tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return tickMsg(t)
		})
	case alertMsg:
		// Add new alert to the list, keeping only the last 5
		if len(m.recentAlerts) >= 5 {
			m.recentAlerts = m.recentAlerts[1:]
		}
		m.recentAlerts = append(m.recentAlerts, string(msg))
		return m, nil
	}
	return m, nil
}

func (m *model) updateIPData() {
	stats := m.monitor.metrics.GetAll()
	ppsStats, ok := stats["ddos_packets_per_second"].(map[string]float64)
	if !ok {
		ppsStats = make(map[string]float64)
	}
	bpsPerIPStats, ok := stats["ddos_bytes_per_second_per_ip"].(map[string]float64)
	if !ok {
		bpsPerIPStats = make(map[string]float64)
	}
	protocolStats, ok := stats["ddos_protocols_per_ip"].(map[string]map[string]int64)
	if !ok {
		protocolStats = make(map[string]map[string]int64)
	}
	suspiciousIPs, ok := stats["ddos_suspicious_ips"].(map[string]int64)
	if !ok {
		suspiciousIPs = make(map[string]int64)
	}

	var newIPData []ipTableRow
	for ip, pps := range ppsStats {
		bps := bpsPerIPStats[ip]
		isSuspicious := suspiciousIPs[ip] == 1

		// Format protocols for display
		protocols := ""
		if protoMap, ok := protocolStats[ip]; ok {
			for p, count := range protoMap {
				protocols += fmt.Sprintf("%s:%d ", p, count)
			}
		}
		if protocols == "" {
			protocols = "N/A"
		}

		newIPData = append(newIPData, ipTableRow{
			IP:         ip,
			PPS:        pps,
			BPS:        bps,
			Protocols:  protocols,
			Suspicious: isSuspicious,
		})
	}

	m.ipData = newIPData
	m.sortIPData() // Sort data after updating
}

func (m *model) sortIPData() {
	sort.Slice(m.ipData, func(i, j int) bool {
		a, b := m.ipData[i], m.ipData[j]
		sortOrder := m.sortAscending // Use m.sortAscending directly

		switch m.sortColumn {
		case "IP":
			if sortOrder {
				return a.IP < b.IP
			} else {
				return a.IP > b.IP
			}
		case "PPS":
			if sortOrder {
				return a.PPS < b.PPS
			} else {
				return a.PPS > b.PPS
			}
		case "BPS":
			if sortOrder {
				return a.BPS < b.BPS
			} else {
				return a.BPS > b.BPS
			}
		case "Protocols":
			if sortOrder {
				return a.Protocols < b.Protocols
			} else {
				return a.Protocols > b.Protocols
			}
		case "Suspicious":
			// Sort suspicious items first if descending, or last if ascending
			if sortOrder {
				return a.Suspicious == false && b.Suspicious == true
			} else {
				return a.Suspicious == true && b.Suspicious == false
			}
		}
		return false // Should not happen
	})
}

// View renders the UI
func (m model) View() string {
	if m.monitor == nil {
		return "Initializing..."
	}

	s := "DDoS Monitoring Dashboard\n\n"

	stats := m.monitor.metrics.GetAll()

	// Overall Statistics
	activeConnections := stats["ddos_active_connections"]
	s += fmt.Sprintf("Active Connections: %v\n", activeConnections)
	suspiciousCount := stats["ddos_suspicious_count"]
	s += fmt.Sprintf("Suspicious Traffic: %v\n", suspiciousCount)
	bps := stats["ddos_bytes_per_second_total"]
	if totalBPS, ok := bps.(float64); ok {
		s += fmt.Sprintf("Total Bytes per Second (BPS): %.2f\n\n", totalBPS)
	} else {
		s += fmt.Sprintf("Total Bytes per Second (BPS): N/A\n\n")
	}

	// Monitored Endpoints
	if len(m.monitor.monitoredEndpoints) > 0 {
		s += fmt.Sprintf("Monitored Endpoints:\n")
		for _, endpoint := range m.monitor.monitoredEndpoints {
			s += fmt.Sprintf("  - %s\n", endpoint)
		}
		s += "\n"
	}

	// IP Statistics Table Header with sort indicators
	ipHeader := fmt.Sprintf("%-20s %-12s %-18s %-25s %-12s", "IP Address", "PPS", "BPS", "Protocols", "Suspicious")
	if m.sortColumn != "" {
		sortIndicator := "▲" // Ascending
		if !m.sortAscending {
			sortIndicator = "▼" // Descending
		}
		switch m.sortColumn {
		case "IP":
			ipHeader = fmt.Sprintf("%-20s %-12s %-18s %-25s %-12s", "IP Address "+sortIndicator, "PPS", "BPS", "Protocols", "Suspicious")
		case "PPS":
			ipHeader = fmt.Sprintf("%-20s %-12s %-18s %-25s %-12s", "IP Address", "PPS "+sortIndicator, "BPS", "Protocols", "Suspicious")
		case "BPS":
			ipHeader = fmt.Sprintf("%-20s %-12s %-18s %-25s %-12s", "IP Address", "PPS", "BPS "+sortIndicator, "Protocols", "Suspicious")
		case "Protocols":
			ipHeader = fmt.Sprintf("%-20s %-12s %-18s %-25s %-12s", "IP Address", "PPS", "BPS", "Protocols "+sortIndicator, "Suspicious")
		case "Suspicious":
			ipHeader = fmt.Sprintf("%-20s %-12s %-18s %-25s %-12s", "IP Address", "PPS", "BPS", "Protocols", "Suspicious "+sortIndicator)
		}
	}
	s += tableHeaderStyle.Render(ipHeader) + "\n"

	for _, row := range m.ipData {
		line := fmt.Sprintf("%-20s %-12.2f %-18.2f %-25s %-12t", row.IP, row.PPS, row.BPS, row.Protocols, row.Suspicious)
		if row.Suspicious {
			line = suspiciousStyle.Render(line)
		}
		s += rowStyle.Render(line) + "\n"
	}

	s += "\n"

	// Recent Alerts
	if len(m.recentAlerts) > 0 {
		s += "Recent Alerts:\n"
		for _, alert := range m.recentAlerts {
			s += fmt.Sprintf("  - %s\n", alert)
		}
		s += "\n"
	}

	s += "Press 1-4 to sort by column, 's' for Suspicious, 'q' to quit.\n" // Add sorting instructions

	style := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("63")).
		Padding(1, 2).
		Width(m.width - 4).
		Height(m.height - 4)

	return style.Render(s)
}

type tickMsg time.Time
