package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type NetworkMonitor struct {
	mu                 sync.RWMutex
	ipStats            map[string]*IPStats
	portStats          map[uint16]*PortStats
	handle             *pcap.Handle
	thresholdPPS       int64
	thresholdBandwidth int64
	windowSize         time.Duration
	metrics            *MetricsCollector
	monitoredEndpoints []string
	networkInterface   string
	programSend        func(tea.Msg)
	whitelistedIPs     map[string]bool
}

func (nm *NetworkMonitor) SetProgramSend(send func(tea.Msg)) {
	nm.programSend = send
}

func (nm *NetworkMonitor) SetWhitelistedIPs(ips []string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.whitelistedIPs = make(map[string]bool)
	for _, ip := range ips {
		nm.whitelistedIPs[ip] = true
	}
}

type IPStats struct {
	PacketCount    int64
	ByteCount      int64
	LastSeen       time.Time
	WindowStart    time.Time
	SuspiciousFlag bool
	Protocols      map[string]int64
	Domain         string // Added for domain resolution
}

type PortStats struct {
	PacketCount int64
	ByteCount   int64
	LastSeen    time.Time
}

func NewNetworkMonitor(thresholdPPS int64, thresholdBandwidth int64, monitoredEndpoints []string, networkInterface string) *NetworkMonitor {
	return &NetworkMonitor{
		ipStats:            make(map[string]*IPStats),
		portStats:          make(map[uint16]*PortStats),
		thresholdPPS:       thresholdPPS,
		thresholdBandwidth: thresholdBandwidth,
		windowSize:         time.Minute,
		metrics:            NewMetricsCollector(),
		monitoredEndpoints: monitoredEndpoints,
		networkInterface:   networkInterface,
		whitelistedIPs:     make(map[string]bool), // Initialize whitelistedIPs
	}
}

func (nm *NetworkMonitor) Start(ctx context.Context) error {
	var err error
	if nm.networkInterface == "" {
		log.Println("No network interface specified. Attempting to find a suitable one...")
		devices, err := pcap.FindAllDevs()
		if err != nil {
			return fmt.Errorf("error finding devices: %v", err)
		}
		for _, device := range devices {
			if len(device.Addresses) > 0 {
				nm.networkInterface = device.Name
				log.Printf("Using network interface: %s", nm.networkInterface)
				break
			}
		}
		if nm.networkInterface == "" {
			return fmt.Errorf("no suitable network interface found. Please specify one using -interface flag or in config.yaml")
		}
	}

	nm.handle, err = pcap.OpenLive(nm.networkInterface, 1600, true, 30*time.Second) // 30-second timeout
	if err != nil {
		return fmt.Errorf("error opening device %s: %v", nm.networkInterface, err)
	}
	defer nm.handle.Close()

	log.Printf("Started network monitoring on interface %s", nm.networkInterface)
	log.Printf("Thresholds: %d PPS, %d bytes/sec", nm.thresholdPPS, nm.thresholdBandwidth)

	go nm.cleanup(ctx)
	go nm.analyzeTraffic(ctx)

	packetSource := gopacket.NewPacketSource(nm.handle, nm.handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return nil
		case packet := <-packetSource.Packets():
			nm.processPacket(packet)
		}
	}
}

func (nm *NetworkMonitor) processPacket(packet gopacket.Packet) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return
	}

	srcIP := ip.SrcIP.String()
	var dstPort uint16
	var protocol string
	packetSize := int64(packet.Metadata().Length)

	switch ip.Protocol {
	case layers.IPProtocolTCP:
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			if tcp, ok := tcpLayer.(*layers.TCP); ok {
				dstPort = uint16(tcp.DstPort)
				protocol = "tcp"
			}
		}
	case layers.IPProtocolUDP:
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			if udp, ok := udpLayer.(*layers.UDP); ok {
				dstPort = uint16(udp.DstPort)
				protocol = "udp"
			}
		}
	case layers.IPProtocolICMPv4:
		protocol = "icmp"
	default:
		protocol = "other"
	}

	now := time.Now()

	stats, exists := nm.ipStats[srcIP]
	if !exists {
		stats = &IPStats{
			WindowStart: now,
			LastSeen:    now,
			Protocols:   make(map[string]int64),
		}
		nm.ipStats[srcIP] = stats
	}

	if now.Sub(stats.WindowStart) > nm.windowSize {
		stats.WindowStart = now
		stats.PacketCount = 0
		stats.ByteCount = 0
	}

	stats.PacketCount++
	stats.ByteCount += packetSize
	stats.LastSeen = now
	stats.Protocols[protocol]++

	// Perform reverse DNS lookup asynchronously
	if stats.Domain == "" {
		go func(ip string, s *IPStats) {
			names, err := net.LookupAddr(ip)
			if err == nil && len(names) > 0 {
				s.Domain = names[0]
			} else {
				s.Domain = "N/A"
			}
		}(srcIP, stats)
	}

	if dstPort > 0 {
		portStats, exists := nm.portStats[dstPort]
		if !exists {
			portStats = &PortStats{LastSeen: now}
			nm.portStats[dstPort] = portStats
		}
		portStats.PacketCount++
		portStats.ByteCount += packetSize
		portStats.LastSeen = now
	}
}

func (nm *NetworkMonitor) analyzeTraffic(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			nm.detectSuspiciousActivity()
		}
	}
}

func (nm *NetworkMonitor) detectSuspiciousActivity() {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	now := time.Now()
	activeCount := int64(0)
	suspiciousCount := int64(0)
	ppsStats := make(map[string]float64)
	bpsStats := make(map[string]float64)
	protocolStats := make(map[string]map[string]int64)
	domainStats := make(map[string]string) // Added for domain stats
	suspiciousIPs := make(map[string]int64)
	totalBPS := float64(0)

	for ip, stats := range nm.ipStats {
		if now.Sub(stats.LastSeen) > time.Minute {
			// Save final stats before cleaning up
			SaveIPStats(ip, stats)
			continue
		}

		activeCount++
		windowDuration := now.Sub(stats.WindowStart).Seconds()
		if windowDuration == 0 {
			continue
		}

		pps := float64(stats.PacketCount) / windowDuration
		bps := float64(stats.ByteCount) / windowDuration

		ppsStats[ip] = pps
		bpsStats[ip] = bps
		protocolStats[ip] = stats.Protocols
		domainStats[ip] = stats.Domain // Store domain
		totalBPS += bps

		suspicious := pps > float64(nm.thresholdPPS) || bps > float64(nm.thresholdBandwidth)

		// Check if the IP is a monitored endpoint and if it's suspicious
		if len(nm.monitoredEndpoints) > 0 {
			for _, endpoint := range nm.monitoredEndpoints {
				if ip == endpoint {
					if suspicious {
						alertMsgText := fmt.Sprintf("ALERT: Monitored endpoint %s is experiencing suspicious activity - PPS: %.2f, BPS: %.2f", ip, pps, bps)
						log.Println(alertMsgText) // Keep in log for debugging/persistence
						if nm.programSend != nil {
							nm.programSend(alertMsg(alertMsgText))
						}
						LogSuspiciousEvent(ip, "DDoS_Attack_Monitored_Endpoint", fmt.Sprintf("PPS: %.2f, BPS: %.2f", pps, bps))
					}
					break
				}
			}
		}

		if suspicious && !stats.SuspiciousFlag {
			// Check if the IP is whitelisted
			if nm.whitelistedIPs[ip] {
				log.Printf("INFO: Whitelisted IP %s exceeded thresholds (PPS: %.2f, BPS: %.2f)", ip, pps, bps)
			} else {
				alertMsgText := fmt.Sprintf("ALERT: Suspicious activity from %s - PPS: %.2f, BPS: %.2f", ip, pps, bps)
				log.Println(alertMsgText) // Keep in log for debugging/persistence
				if nm.programSend != nil {
					nm.programSend(alertMsg(alertMsgText))
				}
				log.Printf("  Protocols: %v", stats.Protocols)
				suspiciousCount++
				LogSuspiciousEvent(ip, "DDoS_Attack_Detected", fmt.Sprintf("PPS: %.2f, BPS: %.2f", pps, bps))
			}
		}

		stats.SuspiciousFlag = suspicious
		if suspicious {
			suspiciousIPs[ip] = 1
		} else {
			suspiciousIPs[ip] = 0
		}
		SaveIPStats(ip, stats)
	}

	nm.metrics.Set("ddos_active_connections", activeCount)
	nm.metrics.Set("ddos_suspicious_count", suspiciousCount)
	nm.metrics.Set("ddos_packets_per_second", ppsStats)
	nm.metrics.Set("ddos_bytes_per_second_total", totalBPS)
	nm.metrics.Set("ddos_bytes_per_second_per_ip", bpsStats)
	nm.metrics.Set("ddos_protocols_per_ip", protocolStats)
	nm.metrics.Set("ddos_domains_per_ip", domainStats) // Expose domain stats
	nm.metrics.Set("ddos_suspicious_ips", suspiciousIPs)
}

func (nm *NetworkMonitor) cleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			nm.mu.Lock()
			now := time.Now()

			for ip, stats := range nm.ipStats {
				if now.Sub(stats.LastSeen) > 10*time.Minute {
					delete(nm.ipStats, ip)
				}
			}

			for port, stats := range nm.portStats {
				if now.Sub(stats.LastSeen) > 10*time.Minute {
					delete(nm.portStats, port)
				}
			}
			nm.mu.Unlock()
		}
	}
}

func (nm *NetworkMonitor) Stop() {
	if nm.handle != nil {
		nm.handle.Close()
	}
}

func (nm *NetworkMonitor) GetStats() map[string]interface{} {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_ips"] = len(nm.ipStats)
	stats["total_ports"] = len(nm.portStats)

	topIPs := make(map[string]int64)
	for ip, stat := range nm.ipStats {
		topIPs[ip] = stat.PacketCount
	}
	stats["top_ips"] = topIPs

	return stats
}