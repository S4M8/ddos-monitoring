package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	yaml "gopkg.in/yaml.v2"
)

func main() {
	var (
		configPath = flag.String("config", "./config.yaml", "Path to the configuration file")
		dbPath     = flag.String("db", "./ddos_monitor.db", "Path to the SQLite database file")
	)
	flag.Parse()

	type Config struct {
		Thresholds struct {
			PPS int64 `yaml:"pps"`
			BPS int64 `yaml:"bps"`
		} `yaml:"thresholds"`
		MonitoredEndpoints []string `yaml:"monitored_endpoints"`
		NetworkInterface   string   `yaml:"network_interface"`
	}

	config := Config{}
	configData, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	err = yaml.Unmarshal(configData, &config)
	if err != nil {
		log.Fatalf("Error unmarshaling config file: %v", err)
	}

	// Override config values with command-line flags if provided
	ppsFlag := flag.Int64("pps", config.Thresholds.PPS, "Packets per second threshold")
	bpsFlag := flag.Int64("bps", config.Thresholds.BPS, "Bytes per second threshold")
	interfaceFlag := flag.String("interface", config.NetworkInterface, "Network interface to monitor")
	flag.Parse() // Parse flags again to pick up overrides

	selectedInterface := *interfaceFlag
	if selectedInterface == "" {
		log.Println("No network interface specified. Launching interactive selector...")
		var err error
		selectedInterface, err = selectInterface()
		if err != nil {
			log.Fatalf("Failed to select network interface: %v", err)
		}
		if selectedInterface == "" {
			log.Fatal("No network interface selected. Exiting.")
		}
		log.Printf("Selected network interface: %s", selectedInterface)
	}

	InitDB(*dbPath)

	// Check if running as root (required for raw sockets)
	if !isElevated() {
		log.Fatal("This program must be run as root (Linux) or as administrator (Windows) for raw socket access")
	}

	monitor := NewNetworkMonitor(*ppsFlag, *bpsFlag, config.MonitoredEndpoints, selectedInterface)

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
	monitor.SetProgramSend(p.Send) // Pass the program's Send method to the monitor
	if _, err := p.Run(); err != nil {
		log.Fatalf("Alas, there's been an error: %v", err)
	}

	monitor.Stop()
	log.Println("Monitoring stopped")
}