package main

import (
    "context"
    "flag"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
)

func main() {
	var (
		ppsLimit    = flag.Int("pps", 1000, "Packets per second threshold")
		bpsLimit    = flag.Int64("bps", 1000000, "Bytes per second threshold")
		metricsPort = flag.String("metrics-port", "8080", "Metrics HTTP server port")
	)
	flag.Parse()

	// Check if running as root (required for raw sockets)
    if !isElevated() {
        log.Fatal("This program must be run as root (Linux) or as administrator (Windows) for raw socket access")
    }
	// Create monitor
	monitor := NewNetworkMonitor(*ppsLimit, *bpsLimit)

	// Start HTTP metrics server
	http.Handle("/metrics", monitor.metrics)
	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		stats := monitor.GetStats()
		fmt.Fprintf(w, "{\n")
		for k, v := range stats {
			fmt.Fprintf(w, "  \"%s\": %v,\n", k, v)
		}
		fmt.Fprintf(w, "}\n")
	})

	go func() {
		log.Printf("Metrics server: http://localhost:%s/metrics", *metricsPort)
		log.Printf("Stats endpoint: http://localhost:%s/stats", *metricsPort)
		if err := http.ListenAndServe(":"+*metricsPort, nil); err != nil {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")
		cancel()
	}()

	// Start monitoring
	if err := monitor.Start(ctx); err != nil {
		log.Fatal(err)
	}

	monitor.Stop()
	log.Println("Monitoring stopped")
}
