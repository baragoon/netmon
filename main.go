package main

import (
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
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
	logPath := flag.String("log", "", "Optional path to log file (logs to stdout if not specified)")

	flag.Parse()

	// Initialize logger with optional file output
	var logWriter io.Writer = os.Stdout
	var logFile *os.File
	var err error

	if *logPath != "" {
		logFile, err = os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		defer logFile.Close()
		// Write to both stdout and file
		logWriter = io.MultiWriter(os.Stdout, logFile)
	}

	logger := log.New(logWriter, "[netmon] ", log.LstdFlags|log.Lshortfile)

	// Load configuration
	config := monitor.DefaultConfig()
	
	// Auto-load config.json if it exists in the current directory and no config path specified
	if *configPath == "" {
		execPath, err := os.Executable()
		if err == nil {
			execDir := filepath.Dir(execPath)
			autoConfigPath := filepath.Join(execDir, "config.json")
			if _, err := os.Stat(autoConfigPath); err == nil {
				logger.Printf("Auto-loading config from: %s", autoConfigPath)
				if err := config.LoadFromFile(autoConfigPath); err != nil {
					logger.Fatalf("Failed to load config: %v", err)
				}
			}
		}
	} else {
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
