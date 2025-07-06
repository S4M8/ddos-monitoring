package main

import (
	"context"
	"log"
	"net"
	"sync"
	"fmt"
	"time"
)

type NetworkMonitor struct {
	mu                 sync.RWMutex
	ipStats            map[string]*IPStats
	portStats          map[uint16]*PortStats
	conn               net.PacketConn
	thresholdPPS       int
	thresholdBandwidth int64
	windowSize         time.Duration
	metrics            *MetricsCollector
}

type IPStats struct {
	PacketCount    int64
	ByteCount      int64
	LastSeen       time.Time
	WindowStart    time.Time
	SuspiciousFlag bool
	Protocols      map[string]int64
}

type PortStats struct {
	PacketCount int64
	ByteCount   int64
	LastSeen    time.Time
}

func NewNetworkMonitor(thresholdPPS int, thresholdBandwidth int64) *NetworkMonitor {
	return &NetworkMonitor{
		ipStats:            make(map[string]*IPStats),
		portStats:          make(map[uint16]*PortStats),
		thresholdPPS:       thresholdPPS,
		thresholdBandwidth: thresholdBandwidth,
		windowSize:         time.Minute,
		metrics:            NewMetricsCollector(),
	}
}

func (nm *NetworkMonitor) Start(ctx context.Context) error {
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		conn, err = net.ListenPacket("ip4:udp", "0.0.0.0")
		if err != nil {
			return fmt.Errorf("failed to create raw socket: %v", err)
		}
	}
	nm.conn = conn

	log.Println("Started network monitoring with raw sockets")
	log.Printf("Thresholds: %d PPS, %d bytes/sec", nm.thresholdPPS, nm.thresholdBandwidth)

	go nm.cleanup(ctx)
	go nm.analyzeTraffic(ctx)

	buffer := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("Error reading packet: %v", err)
				continue
			}
			nm.processPacket(buffer[:n], addr)
		}
	}
}

func (nm *NetworkMonitor) processPacket(data []byte, addr net.Addr) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	ipHeader, err := parseIPv4Header(data)
	if err != nil {
		return
	}

	srcIP := ipHeader.SrcIP.String()
	var dstPort uint16
	var protocol string
	packetSize := int64(len(data))

	headerLen := int(ipHeader.IHL * 4)
	if len(data) < headerLen {
		return
	}

	payload := data[headerLen:]

	switch ipHeader.Protocol {
	case 6: // TCP
		if tcpHeader, err := parseTCPHeader(payload); err == nil {
			dstPort = tcpHeader.DstPort
			protocol = "tcp"
		}
	case 17: // UDP
		if udpHeader, err := parseUDPHeader(payload); err == nil {
			dstPort = udpHeader.DstPort
			protocol = "udp"
		}
	case 1: // ICMP
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
	suspiciousIPs := make(map[string]int64)
	totalBPS := float64(0)

	for ip, stats := range nm.ipStats {
		if now.Sub(stats.LastSeen) > time.Minute {
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
		totalBPS += bps

		suspicious := pps > float64(nm.thresholdPPS) || bps > float64(nm.thresholdBandwidth)

		if suspicious && !stats.SuspiciousFlag {
			log.Printf("ALERT: Suspicious activity from %s - PPS: %.2f, BPS: %.2f",
				ip, pps, bps)
			log.Printf("  Protocols: %v", stats.Protocols)
			suspiciousCount++
		}

		stats.SuspiciousFlag = suspicious
		if suspicious {
			suspiciousIPs[ip] = 1
		} else {
			suspiciousIPs[ip] = 0
		}
	}

	nm.metrics.Set("ddos_active_connections", activeCount)
	nm.metrics.Set("ddos_suspicious_count", suspiciousCount)
	nm.metrics.Set("ddos_packets_per_second", ppsStats)
	nm.metrics.Set("ddos_suspicious_ips", suspiciousIPs)
	nm.metrics.Set("ddos_bytes_per_second", totalBPS)
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
	if nm.conn != nil {
		nm.conn.Close()
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