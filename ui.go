package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	tableHeaderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Bold(true)
	rowStyle         = lipgloss.NewStyle().PaddingRight(2)
	suspiciousStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true) // Red color
	footerStyle      = lipgloss.NewStyle().Padding(1, 2).BorderTop(true).BorderStyle(lipgloss.NormalBorder())
)

type ipTableRow struct {
	IP         string
	PPS        float64
	BPS        float64
	Protocols  string
	Domain     string // Added for domain
	Suspicious bool
}

// Model represents the TUI model
type model struct {
	monitor       *NetworkMonitor
	width         int
	height        int
	ipData        []ipTableRow // Data for the IP table
	recentAlerts  []string     // Stores recent alerts
	sortColumn    string       // Current column being sorted (e.g., "IP", "PPS", "BPS", "Protocols", "Domain", "Suspicious")
	sortAscending bool         // True for ascending, false for descending
	currentView   string       // Current view: "table", "suspicious"
}

const (
	ViewTable      = "default"
	ViewSuspicious = "suspicious"
)

type alertMsg string

// NewModel creates a new model
func NewModel(monitor *NetworkMonitor) tea.Model {
	return model{
		monitor:       monitor,
		recentAlerts:  make([]string, 0, 5), // Initialize with capacity
		sortColumn:    "PPS",                // Default sort column
		sortAscending: false,                // Default sort order (descending for PPS)
		currentView:   ViewTable,            // Default view
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
		case "v": // Toggle views
			if m.currentView == ViewTable {
				m.currentView = ViewSuspicious
			} else {
				m.currentView = ViewTable
			}
		case "1": // Sort by IP
			if m.currentView == ViewTable {
				if m.sortColumn == "IP" {
					m.sortAscending = !m.sortAscending
				} else {
					m.sortColumn = "IP"
					m.sortAscending = true
				}
				m.sortIPData()
			}
		case "2": // Sort by PPS
			if m.currentView == ViewTable {
				if m.sortColumn == "PPS" {
					m.sortAscending = !m.sortAscending
				} else {
					m.sortColumn = "PPS"
					m.sortAscending = false // Default to descending for PPS
				}
				m.sortIPData()
			}
		case "3": // Sort by BPS
			if m.currentView == ViewTable {
				if m.sortColumn == "BPS" {
					m.sortAscending = !m.sortAscending
				} else {
					m.sortColumn = "BPS"
					m.sortAscending = false // Default to descending for BPS
				}
				m.sortIPData()
			}
		case "4": // Sort by Protocols
			if m.currentView == ViewTable {
				if m.sortColumn == "Protocols" {
					m.sortAscending = !m.sortAscending
				} else {
					m.sortColumn = "Protocols"
					m.sortAscending = true
				}
				m.sortIPData()
			}
		case "5": // Sort by Domain
			if m.currentView == ViewTable {
				if m.sortColumn == "Domain" {
					m.sortAscending = !m.sortAscending
				} else {
					m.sortColumn = "Domain"
					m.sortAscending = true
				}
				m.sortIPData()
			}
		case "s": // Sort by Suspicious
			if m.currentView == ViewTable {
				if m.sortColumn == "Suspicious" {
					m.sortAscending = !m.sortAscending
				} else {
					m.sortColumn = "Suspicious"
					m.sortAscending = false // Default to descending (suspicious first)
				}
				m.sortIPData()
			}
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
	domainStats, ok := stats["ddos_domains_per_ip"].(map[string]string) // Get domain stats
	if !ok {
		domainStats = make(map[string]string)
	}
	suspiciousIPs, ok := stats["ddos_suspicious_ips"].(map[string]int64)
	if !ok {
		suspiciousIPs = make(map[string]int64)
	}

	var newIPData []ipTableRow
	for ip, pps := range ppsStats {
		bps := bpsPerIPStats[ip]
		isSuspicious := suspiciousIPs[ip] == 1
		domain := domainStats[ip] // Get domain for this IP

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
			Domain:     domain, // Assign domain
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
		case "Domain": // Sort by Domain
			if sortOrder {
				return a.Domain < b.Domain
			} else {
				return a.Domain > b.Domain
			}
		case "Suspicious":
			// Sort suspicious items first if descending, or last if ascending
			if sortOrder {
				return !a.Suspicious && b.Suspicious
			} else {
				return a.Suspicious && !b.Suspicious
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

	var s strings.Builder
	stats := m.monitor.metrics.GetAll()

	// Overall Statistics
	activeConnections := stats["ddos_active_connections"]
	suspiciousCount := stats["ddos_suspicious_count"]
	bps := stats["ddos_bytes_per_second_total"]

	s.WriteString("DDoS Monitoring Dashboard\n\n")
	s.WriteString(fmt.Sprintf("Active Connections: %v\n", activeConnections))
	s.WriteString(fmt.Sprintf("Suspicious Traffic: %v\n", suspiciousCount))
	if totalBPS, ok := bps.(float64); ok {
		s.WriteString(fmt.Sprintf("Total Bytes per Second (BPS): %.2f\n\n", totalBPS))
	} else {
		s.WriteString("Total Bytes per Second (BPS): N/A\n\n")
	}

	// Monitored Endpoints
	if len(m.monitor.monitoredEndpoints) > 0 {
		s.WriteString("Monitored Endpoints:\n")
		for _, endpoint := range m.monitor.monitoredEndpoints {
			s.WriteString(fmt.Sprintf("  - %s\n", endpoint))
		}
		s.WriteString("\n")
	}

	// Current View Label
	viewLabel := "Current View: " + strings.Title(m.currentView) + "\n\n"
	s.WriteString(viewLabel)

	// Main content area based on current view
	mainContent := ""
	switch m.currentView {
	case ViewTable:
		ipHeader := fmt.Sprintf("%-20s %-12s %-18s %-25s %-30s", "IP Address", "PPS", "BPS", "Protocols", "Domain")
		if m.sortColumn != "" {
			sortIndicator := "▲"
			if !m.sortAscending {
				sortIndicator = "▼"
			}
			switch m.sortColumn {
			case "IP":
				ipHeader = fmt.Sprintf("%-20s %-12s %-18s %-25s %-30s", "IP Address "+sortIndicator, "PPS", "BPS", "Protocols", "Domain")
			case "PPS":
				ipHeader = fmt.Sprintf("%-20s %-12s %-18s %-25s %-30s", "IP Address", "PPS "+sortIndicator, "BPS", "Protocols", "Domain")
			case "BPS":
				ipHeader = fmt.Sprintf("%-20s %-12s %-18s %-25s %-30s", "IP Address", "PPS", "BPS "+sortIndicator, "Protocols", "Domain")
			case "Protocols":
				ipHeader = fmt.Sprintf("%-20s %-12s %-18s %-25s %-30s", "IP Address", "PPS", "BPS", "Protocols "+sortIndicator, "Domain")
			case "Domain":
				ipHeader = fmt.Sprintf("%-20s %-12s %-18s %-25s %-30s", "IP Address", "PPS", "BPS", "Protocols", "Domain "+sortIndicator)
			}
		}
		mainContent += tableHeaderStyle.Render(ipHeader) + "\n"

		for _, row := range m.ipData {
			line := fmt.Sprintf("%-20s %-12.2f %-18.2f %-25s %-30s", row.IP, row.PPS, row.BPS, row.Protocols, m.truncateDomain(row.Domain, 28))
			if row.Suspicious {
				line = suspiciousStyle.Render(line)
			}
			mainContent += rowStyle.Render(line) + "\n"
		}

	case ViewSuspicious:
		// Render suspicious IPs table
		suspiciousIPsMap, ok := stats["ddos_suspicious_ips"].(map[string]int64)
		if !ok {
			suspiciousIPsMap = make(map[string]int64)
		}

		var suspiciousRows []ipTableRow
		for _, row := range m.ipData {
			if suspiciousIPsMap[row.IP] == 1 {
				suspiciousRows = append(suspiciousRows, row)
			}
		}

		mainContent += tableHeaderStyle.Render(fmt.Sprintf("%-20s %-12s %-18s %-25s %-30s", "IP Address", "PPS", "BPS", "Protocols", "Domain")) + "\n"
		for _, row := range suspiciousRows {
			line := fmt.Sprintf("%-20s %-12.2f %-18.2f %-25s %-30s", row.IP, row.PPS, row.BPS, row.Protocols, m.truncateDomain(row.Domain, 28))
			if row.Suspicious {
				line = suspiciousStyle.Render(line)
			}
			mainContent += rowStyle.Render(line) + "\n"
		}
	}

	s.WriteString(mainContent)
	s.WriteString("\n")

	// Recent Alerts
	if len(m.recentAlerts) > 0 {
		s.WriteString("Recent Alerts:\n")
		for _, alert := range m.recentAlerts {
			s.WriteString(fmt.Sprintf("  - %s\n", alert))
		}
		s.WriteString("\n")
	}

	// Controls (fixed at the bottom)
	nextView := ViewSuspicious
	if m.currentView == ViewSuspicious {
		nextView = ViewTable
	}
	controls := fmt.Sprintf("Press 'v' to change view to %s, 1-5 to sort by column, 'q' to quit.", strings.Title(nextView))
	s.WriteString(footerStyle.Render(controls))

	style := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("63")).
		Padding(1, 2).
		Width(m.width - 4).
		Height(m.height - 4)

	return style.Render(s.String())
}

func (m model) truncateDomain(domain string, maxLength int) string {
	if len(domain) <= maxLength {
		return domain
	}
	return domain[:maxLength-3] + "..."
}

type tickMsg time.Time
