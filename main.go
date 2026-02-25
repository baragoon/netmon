package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netmon/monitor"
)

func main() {
	// Command-line flags
	interval := flag.Duration("interval", 5*time.Second, "Monitoring interval")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	alertOnly := flag.Bool("alerts-only", false, "Only show alerts for abnormal activity")
	configPath := flag.String("config", "", "Path to configuration file")

	flag.Parse()

	// Initialize logger
	logger := log.New(os.Stdout, "[netmon] ", log.LstdFlags|log.Lshortfile)

	// Load configuration
	config := monitor.DefaultConfig()
	if *configPath != "" {
		if err := config.LoadFromFile(*configPath); err != nil {
			logger.Fatalf("Failed to load config: %v", err)
		}
	}

	config.Verbose = *verbose
	config.AlertsOnly = *alertOnly
	config.Interval = *interval

	// Create monitor
	m, err := monitor.NewConnectionMonitor(config, logger)
	if err != nil {
		logger.Fatalf("Failed to create monitor: %v", err)
	}

	logger.Printf("Starting network connections monitor (interval: %v)", *interval)
	logger.Printf("Watching for abnormal activity: %v", config.AnomalousPatterns)

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Run monitor in background
	stopChan := make(chan struct{})
	go m.Start(stopChan)

	// Wait for signal
	sig := <-sigChan
	logger.Printf("Received signal: %v, shutting down...", sig)
	close(stopChan)

	// Give it time to gracefully shutdown
	time.Sleep(1 * time.Second)
	logger.Println("Monitor stopped")
}
