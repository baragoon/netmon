package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"netmon/monitor"

	"github.com/fsnotify/fsnotify"
)

func main() {
	// Command-line flags
	interval := flag.Duration("interval", 5*time.Second, "Monitoring interval")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	alertOnly := flag.Bool("alerts-only", false, "Only show alerts for abnormal activity")
	configPath := flag.String("config", "", "Path to configuration file")
	logPath := flag.String("log", "", "Optional path to log file (logs to stdout if not specified)")

	// Customize usage output to use double-dash format
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of netmon:\n")
		flag.VisitAll(func(f *flag.Flag) {
			// Extract flag name and type
			name, usage := flag.UnquoteUsage(f)

			// Format the flag line
			if name == "" {
				// Boolean flag
				fmt.Fprintf(os.Stderr, "  --%s\n", f.Name)
			} else {
				// Flag with value
				fmt.Fprintf(os.Stderr, "  --%s %s\n", f.Name, name)
			}

			// Print usage description with proper indentation
			fmt.Fprintf(os.Stderr, "        %s", usage)

			// Add default value if not a zero value
			if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
				fmt.Fprintf(os.Stderr, " (default %s)", f.DefValue)
			}
			fmt.Fprintf(os.Stderr, "\n")
		})
	}

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
	var actualConfigPath string

	// Auto-load config.json if it exists in the current directory and no config path specified
	if *configPath == "" {
		execPath, err := os.Executable()
		if err == nil {
			execDir := filepath.Dir(execPath)
			autoConfigPath := filepath.Join(execDir, "config.json")
			if _, err := os.Stat(autoConfigPath); err == nil {
				actualConfigPath = autoConfigPath
				logger.Printf("Auto-loading config from: %s", actualConfigPath)
				if err := config.LoadFromFile(actualConfigPath); err != nil {
					logger.Fatalf("Failed to load config: %v", err)
				}
			}
		}
	} else {
		actualConfigPath = *configPath
		if err := config.LoadFromFile(actualConfigPath); err != nil {
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

	// Setup config file watcher if config path is known
	if actualConfigPath != "" {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			logger.Printf("Warning: Failed to create config file watcher: %v", err)
		} else {
			defer watcher.Close()

			err = watcher.Add(actualConfigPath)
			if err != nil {
				logger.Printf("Warning: Failed to watch config file: %v", err)
			} else {
				logger.Printf("Watching config file for changes: %s", actualConfigPath)

				// Config file change handler
				go func() {
					for {
						select {
						case event, ok := <-watcher.Events:
							if !ok {
								return
							}

							// React to write or create events
							if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
								logger.Printf("Config file changed, reloading: %s", actualConfigPath)

								newConfig := monitor.DefaultConfig()
								if err := newConfig.LoadFromFile(actualConfigPath); err != nil {
									logger.Printf("Error reloading config: %v", err)
									continue
								}

								// Apply CLI flag overrides
								newConfig.Verbose = *verbose
								newConfig.AlertsOnly = *alertOnly
								newConfig.Interval = *interval

								// Update monitor config
								m.UpdateConfig(newConfig)
							}

						case err, ok := <-watcher.Errors:
							if !ok {
								return
							}
							logger.Printf("Config watcher error: %v", err)
						}
					}
				}()
			}
		}
	}

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
