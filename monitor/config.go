package monitor

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

// PortRange represents an inclusive port range.
type PortRange struct {
	Start int
	End   int
}

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

	// Per-process remote port exclusions for alerting, used to reduce noise
	// (for example ephemeral client ports used by browsers/runners).
	// Key is lowercase process name, value is list of inclusive ranges.
	ProcessPortExclusions map[string][]PortRange

	// Explicit allowlist for remote IPs/CIDRs used to suppress high-port alerts.
	// Applies in addition to built-in loopback/private/link-local suppression.
	AllowedRemoteIPs map[string]bool
	AllowedRemoteCIDRs []*net.IPNet

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
		ProcessPortExclusions: map[string][]PortRange{},
		AllowedRemoteIPs: map[string]bool{},
		AllowedRemoteCIDRs: []*net.IPNet{},
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
		ProcessPortExclusions map[string][]string `json:"process_port_exclusions"`
		AllowedRemoteIPs    []string            `json:"allowed_remote_ips"`
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

	if len(jc.ProcessPortExclusions) > 0 {
		c.ProcessPortExclusions = make(map[string][]PortRange)
		for process, specs := range jc.ProcessPortExclusions {
			processName := strings.ToLower(strings.TrimSpace(process))
			if processName == "" {
				continue
			}

			ranges := make([]PortRange, 0, len(specs))
			for _, spec := range specs {
				portRange, err := parsePortRangeSpec(spec)
				if err != nil {
					log.Printf("Ignoring invalid process_port_exclusions entry %q for %s: %v", spec, processName, err)
					continue
				}
				ranges = append(ranges, portRange)
			}

			if len(ranges) > 0 {
				c.ProcessPortExclusions[processName] = ranges
			}
		}
	}

	if len(jc.AllowedRemoteIPs) > 0 {
		c.AllowedRemoteIPs = make(map[string]bool)
		c.AllowedRemoteCIDRs = make([]*net.IPNet, 0)

		for _, entry := range jc.AllowedRemoteIPs {
			trimmed := strings.TrimSpace(entry)
			if trimmed == "" {
				continue
			}

			if strings.Contains(trimmed, "/") {
				_, cidr, err := net.ParseCIDR(trimmed)
				if err != nil {
					log.Printf("Ignoring invalid allowed_remote_ips CIDR %q: %v", trimmed, err)
					continue
				}
				c.AllowedRemoteCIDRs = append(c.AllowedRemoteCIDRs, cidr)
				continue
			}

			parsedIP := net.ParseIP(trimmed)
			if parsedIP == nil {
				log.Printf("Ignoring invalid allowed_remote_ips entry %q", trimmed)
				continue
			}

			c.AllowedRemoteIPs[parsedIP.String()] = true
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

// IsProcessPortExcluded returns true if the process has an exclusion for the given port.
func (c *Config) IsProcessPortExcluded(processName string, port int) bool {
	if c == nil || len(c.ProcessPortExclusions) == 0 || port < 0 {
		return false
	}

	normalizedProcessName := strings.ToLower(strings.TrimSpace(processName))
	ranges, exists := c.ProcessPortExclusions[normalizedProcessName]
	if !exists {
		return false
	}

	for _, portRange := range ranges {
		if port >= portRange.Start && port <= portRange.End {
			return true
		}
	}

	return false
}

func parsePortRangeSpec(spec string) (PortRange, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return PortRange{}, fmt.Errorf("empty port range")
	}

	if strings.Contains(trimmed, "-") {
		parts := strings.SplitN(trimmed, "-", 2)
		if len(parts) != 2 {
			return PortRange{}, fmt.Errorf("invalid range format")
		}

		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return PortRange{}, fmt.Errorf("invalid range start")
		}

		end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return PortRange{}, fmt.Errorf("invalid range end")
		}

		if start < 0 || end > 65535 || start > end {
			return PortRange{}, fmt.Errorf("range must satisfy 0 <= start <= end <= 65535")
		}

		return PortRange{Start: start, End: end}, nil
	}

	port, err := strconv.Atoi(trimmed)
	if err != nil {
		return PortRange{}, fmt.Errorf("invalid port")
	}

	if port < 0 || port > 65535 {
		return PortRange{}, fmt.Errorf("port must be in 0..65535")
	}

	return PortRange{Start: port, End: port}, nil
}

// IsRemoteIPHighPortExcluded returns true when high-port alerts should be suppressed
// for the given remote IP. Built-in exclusions include loopback/private/link-local
// ranges (IPv4 + IPv6), and custom entries from allowed_remote_ips.
func (c *Config) IsRemoteIPHighPortExcluded(remoteIP string) bool {
	parsedIP := net.ParseIP(strings.TrimSpace(remoteIP))
	if parsedIP == nil {
		return false
	}

	if parsedIP.IsLoopback() || parsedIP.IsPrivate() || parsedIP.IsLinkLocalUnicast() {
		return true
	}

	if c == nil {
		return false
	}

	if c.AllowedRemoteIPs[parsedIP.String()] {
		return true
	}

	for _, cidr := range c.AllowedRemoteCIDRs {
		if cidr.Contains(parsedIP) {
			return true
		}
	}

	return false
}
