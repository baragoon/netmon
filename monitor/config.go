package monitor

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"time"
)

// Config holds the monitor configuration
type Config struct {
	// Monitoring interval
	Interval time.Duration

	// Rate limit for LISTEN alerts in logs (default: 1m)
	ListenAlertCooldown time.Duration

	// Ports to watch for (non-standard)
	StandardPorts map[int]bool

	// Anomalous patterns to alert on
	AnomalousPatterns map[string]bool

	// Process names to watch
	WatchProcesses map[string]bool

	// Verbose output
	Verbose bool

	// Only show alerts, not normal activity
	AlertsOnly bool

	// PID to focus on (0 = all)
	PID int

	// Notification configuration
	Notifications *NotificationConfig
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Interval:            5 * time.Second,
		ListenAlertCooldown: 1 * time.Minute,
		StandardPorts: map[int]bool{
			// HTTP/HTTPS
			80:  true,
			443: true,
			// DNS
			53: true,
		},
		AnomalousPatterns: map[string]bool{
			"ssh":         true,  // SSH connections (port 22)
			"telnet":      true,  // Telnet (port 23)
			"private_ip":  false, // Connections to private IPs
			"external":    false, // All external connections
			"high_ports":  false, // Ports > 49152
			"low_ports":   false, // Privileged ports < 1024
		},
		WatchProcesses: map[string]bool{},
		Verbose:        false,
		AlertsOnly:     false,
		PID:            0,
		Notifications:  &NotificationConfig{Enabled: false},
	}
}

// LoadFromFile loads configuration from a JSON file
func (c *Config) LoadFromFile(path string) error {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	type jsonConfig struct {
		Interval            string              `json:"interval"`
		ListenAlertCooldown string              `json:"listen_alert_cooldown"`
		StandardPorts       []int               `json:"standard_ports"`
		AnomalousPatterns   []string            `json:"anomalous_patterns"`
		WatchProcesses      []string            `json:"watch_processes"`
		Verbose             bool                `json:"verbose"`
		AlertsOnly          bool                `json:"alerts_only"`
		PID                 int                 `json:"pid"`
		Notifications       *NotificationConfig `json:"notifications"`
	}

	var jc jsonConfig
	if err := json.Unmarshal(content, &jc); err != nil {
		return err
	}

	if jc.Interval != "" {
		if d, err := time.ParseDuration(jc.Interval); err == nil {
			c.Interval = d
		}
	}

	if jc.ListenAlertCooldown != "" {
		if d, err := time.ParseDuration(jc.ListenAlertCooldown); err == nil {
			c.ListenAlertCooldown = d
		}
	}

	if len(jc.StandardPorts) > 0 {
		c.StandardPorts = make(map[int]bool)
		for _, p := range jc.StandardPorts {
			c.StandardPorts[p] = true
		}
	}

	if len(jc.AnomalousPatterns) > 0 {
		c.AnomalousPatterns = make(map[string]bool)
		for _, p := range jc.AnomalousPatterns {
			c.AnomalousPatterns[p] = true
		}
	}

	if len(jc.WatchProcesses) > 0 {
		c.WatchProcesses = make(map[string]bool)
		for _, p := range jc.WatchProcesses {
			c.WatchProcesses[p] = true
		}
	}

	c.Verbose = jc.Verbose
	c.AlertsOnly = jc.AlertsOnly
	c.PID = jc.PID

	if jc.Notifications != nil {
		c.Notifications = jc.Notifications
		// Log notification configuration status
		if jc.Notifications.Enabled {
			var enabledProviders []string
			if jc.Notifications.Pushover != nil && jc.Notifications.Pushover.Enabled {
				enabledProviders = append(enabledProviders, "Pushover")
			}
			if jc.Notifications.Ntfy != nil && jc.Notifications.Ntfy.Enabled {
				enabledProviders = append(enabledProviders, "Ntfy")
			}
			if jc.Notifications.Pushbullet != nil && jc.Notifications.Pushbullet.Enabled {
				enabledProviders = append(enabledProviders, "Pushbullet")
			}
			if jc.Notifications.Telegram != nil && jc.Notifications.Telegram.Enabled {
				enabledProviders = append(enabledProviders, "Telegram")
			}
			if jc.Notifications.Webhook != nil && jc.Notifications.Webhook.Enabled {
				enabledProviders = append(enabledProviders, "Webhook")
			}
			if len(enabledProviders) > 0 {
				log.Printf("Notifications enabled with providers: %v", enabledProviders)
			} else {
				log.Printf("Notifications enabled but no providers configured")
			}
			if jc.Notifications.NotificationCooldownStr != "" {
				log.Printf("Notification cooldown: %s", jc.Notifications.NotificationCooldownStr)
			}
		} else {
			log.Printf("Notifications disabled")
		}
	}

	return nil
}
