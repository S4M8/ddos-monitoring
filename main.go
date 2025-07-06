package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	var (
		ppsLimit    = flag.Int("pps", 1000, "Packets per second threshold")
		bpsLimit    = flag.Int64("bps", 1000000, "Bytes per second threshold")
	)
	flag.Parse()

	// Check if running as root (required for raw sockets)
	if !isElevated() {
		log.Fatal("This program must be run as root (Linux) or as administrator (Windows) for raw socket access")
	}

	monitor := NewNetworkMonitor(*ppsLimit, *bpsLimit)

	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")
		cancel()
	}()

	go func() {
		if err := monitor.Start(ctx); err != nil {
			log.Fatal(err)
		}
	}()

	p := tea.NewProgram(NewModel(monitor))
	if _, err := p.Run(); err != nil {
		log.Fatalf("Alas, there's been an error: %v", err)
	}

	monitor.Stop()
	log.Println("Monitoring stopped")
}
