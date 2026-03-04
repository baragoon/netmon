package monitor

import (
	"log"
	"os"
	"testing"
)

// TestAnalyzeConnection_UDPPattern tests UDP pattern detection with standard UDP ports
func TestAnalyzeConnection_UDPPattern(t *testing.T) {
	config := DefaultConfig()
	config.AnomalousPatterns["udp"] = true // Enable UDP pattern detection

	logger := log.New(os.Stdout, "[test] ", log.LstdFlags)
	monitor, err := NewConnectionMonitor(config, logger)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	tests := []struct {
		name          string
		conn          *Connection
		expectAnomaly bool
		expectReason  string
	}{
		{
			name: "UDP to standard DNS port (should not alert)",
			conn: &Connection{
				ProcessName: "systemd-resolved",
				Protocol:    "udp",
				RemoteIP:    "8.8.8.8",
				RemotePort:  53, // DNS - standard UDP port
			},
			expectAnomaly: false,
		},
		{
			name: "UDP to standard NTP port (should not alert)",
			conn: &Connection{
				ProcessName: "ntpd",
				Protocol:    "udp",
				RemoteIP:    "pool.ntp.org",
				RemotePort:  123, // NTP - standard UDP port
			},
			expectAnomaly: false,
		},
		{
			name: "UDP to standard DHCP port 67 (should not alert)",
			conn: &Connection{
				ProcessName: "dhclient",
				Protocol:    "udp",
				RemoteIP:    "192.168.1.1",
				RemotePort:  67, // DHCP - standard UDP port
			},
			expectAnomaly: false,
		},
		{
			name: "UDP to standard DHCP port 68 (should not alert)",
			conn: &Connection{
				ProcessName: "dhclient",
				Protocol:    "udp",
				RemoteIP:    "192.168.1.1",
				RemotePort:  68, // DHCP - standard UDP port
			},
			expectAnomaly: false,
		},
		{
			name: "UDP to non-standard port (should alert)",
			conn: &Connection{
				ProcessName: "malware",
				Protocol:    "udp",
				RemoteIP:    "203.0.113.42",
				RemotePort:  8888, // Non-standard UDP port
			},
			expectAnomaly: true,
			expectReason:  "UDP_TRAFFIC",
		},
		{
			name: "UDP to high non-standard port (should alert)",
			conn: &Connection{
				ProcessName: "suspicious",
				Protocol:    "udp",
				RemoteIP:    "198.51.100.1",
				RemotePort:  54321, // Non-standard UDP port
			},
			expectAnomaly: true,
			expectReason:  "UDP_TRAFFIC",
		},
		{
			name: "UDP to port 0 (should not alert)",
			conn: &Connection{
				ProcessName: "test",
				Protocol:    "udp",
				RemoteIP:    "192.168.1.1",
				RemotePort:  0,
			},
			expectAnomaly: false,
		},
		{
			name: "UDP to private IP non-standard port (should not alert due to IP exclusion)",
			conn: &Connection{
				ProcessName: "app",
				Protocol:    "udp",
				RemoteIP:    "192.168.1.1",
				RemotePort:  9999,
			},
			expectAnomaly: false, // Private IPs are excluded by default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset connection state
			tt.conn.IsAnomalous = false
			tt.conn.AnomalousReasons = nil

			monitor.analyzeConnection(tt.conn)

			if tt.conn.IsAnomalous != tt.expectAnomaly {
				t.Errorf("Expected IsAnomalous=%v, got %v", tt.expectAnomaly, tt.conn.IsAnomalous)
			}

			if tt.expectAnomaly && tt.expectReason != "" {
				found := false
				for _, reason := range tt.conn.AnomalousReasons {
					if reason == tt.expectReason || (tt.expectReason == "UDP_TRAFFIC" && len(reason) > 11 && reason[:11] == "UDP_TRAFFIC") {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected reason containing %q, got %v", tt.expectReason, tt.conn.AnomalousReasons)
				}
			}
		})
	}
}

// TestAnalyzeConnection_UDPPattern_Disabled tests that UDP alerts don't trigger when pattern is disabled
func TestAnalyzeConnection_UDPPattern_Disabled(t *testing.T) {
	config := DefaultConfig()
	config.AnomalousPatterns["udp"] = false // Disable UDP pattern detection

	logger := log.New(os.Stdout, "[test] ", log.LstdFlags)
	monitor, err := NewConnectionMonitor(config, logger)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	conn := &Connection{
		ProcessName: "app",
		Protocol:    "udp",
		RemoteIP:    "8.8.8.8",
		RemotePort:  9999, // Non-standard port
	}

	monitor.analyzeConnection(conn)

	// Should not alert on UDP when pattern is disabled
	for _, reason := range conn.AnomalousReasons {
		if len(reason) > 11 && reason[:11] == "UDP_TRAFFIC" {
			t.Errorf("UDP pattern should not alert when disabled, but got reason: %s", reason)
		}
	}
}

// TestAnalyzeConnection_CustomUDPPorts tests custom UDP standard ports
func TestAnalyzeConnection_CustomUDPPorts(t *testing.T) {
	config := DefaultConfig()
	config.AnomalousPatterns["udp"] = true

	// Add WireGuard port as standard UDP port
	config.StandardPortsUDP[51820] = true

	logger := log.New(os.Stdout, "[test] ", log.LstdFlags)
	monitor, err := NewConnectionMonitor(config, logger)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	conn := &Connection{
		ProcessName: "wireguard",
		Protocol:    "udp",
		RemoteIP:    "203.0.113.1",
		RemotePort:  51820, // WireGuard - now a standard port
	}

	monitor.analyzeConnection(conn)

	// Should not alert because 51820 is now a standard UDP port
	if conn.IsAnomalous {
		for _, reason := range conn.AnomalousReasons {
			if len(reason) > 11 && reason[:11] == "UDP_TRAFFIC" {
				t.Errorf("Should not alert on custom standard UDP port 51820, but got reason: %s", reason)
			}
		}
	}
}

// TestAnalyzeConnection_TCPStandardPorts tests TCP standard port handling
func TestAnalyzeConnection_TCPStandardPorts(t *testing.T) {
	config := DefaultConfig()
	logger := log.New(os.Stdout, "[test] ", log.LstdFlags)
	monitor, err := NewConnectionMonitor(config, logger)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	tests := []struct {
		name       string
		remotePort int
		state      string
		shouldFlag bool
	}{
		{"HTTP port 80", 80, "ESTABLISHED", false},
		{"HTTPS port 443", 443, "ESTABLISHED", false},
		{"DNS port 53", 53, "ESTABLISHED", false},
		{"SSH port 22", 22, "ESTABLISHED", true}, // SSH should still alert via ssh pattern
		{"Non-standard port", 8080, "ESTABLISHED", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &Connection{
				ProcessName: "curl",
				Protocol:    "tcp",
				RemoteIP:    "8.8.8.8",
				RemotePort:  tt.remotePort,
				State:       tt.state,
			}

			monitor.analyzeConnection(conn)

			// For non-SSH ports, should not flag
			if !tt.shouldFlag && conn.IsAnomalous {
				t.Errorf("Port %d should not be flagged, but got reasons: %v", tt.remotePort, conn.AnomalousReasons)
			}
		})
	}
}

// TestAnalyzeConnection_ListenPorts tests LISTEN port detection with separate TCP/UDP standard ports
func TestAnalyzeConnection_ListenPorts(t *testing.T) {
	config := DefaultConfig()
	logger := log.New(os.Stdout, "[test] ", log.LstdFlags)
	monitor, err := NewConnectionMonitor(config, logger)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	tests := []struct {
		name          string
		conn          *Connection
		expectAnomaly bool
		expectReason  string
	}{
		{
			name: "TCP LISTEN on standard port 80",
			conn: &Connection{
				ProcessName: "nginx",
				Protocol:    "tcp",
				LocalPort:   80,
				State:       "LISTEN",
			},
			expectAnomaly: false,
		},
		{
			name: "TCP LISTEN on standard port 443",
			conn: &Connection{
				ProcessName: "nginx",
				Protocol:    "tcp",
				LocalPort:   443,
				State:       "LISTEN",
			},
			expectAnomaly: false,
		},
		{
			name: "UDP LISTEN on standard port 53",
			conn: &Connection{
				ProcessName: "named",
				Protocol:    "udp",
				LocalPort:   53,
				State:       "LISTEN",
			},
			expectAnomaly: false,
		},
		{
			name: "TCP LISTEN on non-standard port",
			conn: &Connection{
				ProcessName: "backdoor",
				Protocol:    "tcp",
				LocalPort:   8888,
				State:       "LISTEN",
			},
			expectAnomaly: true,
			expectReason:  "LISTEN",
		},
		{
			name: "UDP LISTEN on non-standard port",
			conn: &Connection{
				ProcessName: "malware",
				Protocol:    "udp",
				LocalPort:   9999,
				State:       "LISTEN",
			},
			expectAnomaly: true,
			expectReason:  "LISTEN",
		},
		{
			name: "TCP LISTEN on port 0 (should not alert)",
			conn: &Connection{
				ProcessName: "test",
				Protocol:    "tcp",
				LocalPort:   0,
				State:       "LISTEN",
			},
			expectAnomaly: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.conn.IsAnomalous = false
			tt.conn.AnomalousReasons = nil

			monitor.analyzeConnection(tt.conn)

			if tt.conn.IsAnomalous != tt.expectAnomaly {
				t.Errorf("Expected IsAnomalous=%v, got %v (reasons: %v)", tt.expectAnomaly, tt.conn.IsAnomalous, tt.conn.AnomalousReasons)
			}

			if tt.expectAnomaly && tt.expectReason != "" {
				found := false
				for _, reason := range tt.conn.AnomalousReasons {
					if len(reason) >= len(tt.expectReason) && reason[:len(tt.expectReason)] == tt.expectReason {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected reason containing %q, got %v", tt.expectReason, tt.conn.AnomalousReasons)
				}
			}
		})
	}
}

// TestAnalyzeConnection_SSHPattern tests SSH detection
func TestAnalyzeConnection_SSHPattern(t *testing.T) {
	config := DefaultConfig()
	config.AnomalousPatterns["ssh"] = true

	logger := log.New(os.Stdout, "[test] ", log.LstdFlags)
	monitor, err := NewConnectionMonitor(config, logger)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	conn := &Connection{
		ProcessName: "ssh",
		Protocol:    "tcp",
		RemoteIP:    "203.0.113.42",
		RemotePort:  22,
		State:       "ESTABLISHED",
	}

	monitor.analyzeConnection(conn)

	if !conn.IsAnomalous {
		t.Error("SSH connection should be flagged as anomalous")
	}

	found := false
	for _, reason := range conn.AnomalousReasons {
		if reason == "SSH_OUTBOUND" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected SSH_OUTBOUND reason, got %v", conn.AnomalousReasons)
	}
}

// TestAnalyzeConnection_TelnetPattern tests Telnet detection
func TestAnalyzeConnection_TelnetPattern(t *testing.T) {
	config := DefaultConfig()
	config.AnomalousPatterns["telnet"] = true

	logger := log.New(os.Stdout, "[test] ", log.LstdFlags)
	monitor, err := NewConnectionMonitor(config, logger)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	conn := &Connection{
		ProcessName: "telnet",
		Protocol:    "tcp",
		RemoteIP:    "203.0.113.42",
		RemotePort:  23,
		State:       "ESTABLISHED",
	}

	monitor.analyzeConnection(conn)

	if !conn.IsAnomalous {
		t.Error("Telnet connection should be flagged as anomalous")
	}

	found := false
	for _, reason := range conn.AnomalousReasons {
		if reason == "TELNET_OUTBOUND" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected TELNET_OUTBOUND reason, got %v", conn.AnomalousReasons)
	}
}

// TestAnalyzeConnection_PrivateIPPattern tests private IP detection
// Note: Private IPs are excluded by IsRemoteIPExcluded by default, so this pattern
// doesn't actually trigger for private IPs unless they're manually added to allowed list
func TestAnalyzeConnection_PrivateIPPattern(t *testing.T) {
	config := DefaultConfig()
	config.AnomalousPatterns["private_ip"] = true

	logger := log.New(os.Stdout, "[test] ", log.LstdFlags)
	monitor, err := NewConnectionMonitor(config, logger)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	tests := []struct {
		name          string
		remoteIP      string
		expectAnomaly bool
	}{
		// Private IPs are excluded by IsRemoteIPExcluded, so they won't trigger alerts
		{"Private 10.x.x.x", "10.0.0.1", false},
		{"Private 192.168.x.x", "192.168.1.1", false},
		{"Private 172.16.x.x", "172.16.0.1", false},
		{"Public IP", "8.8.8.8", false}, // Not a private IP
		{"Loopback", "127.0.0.1", false}, // Loopback is also excluded
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &Connection{
				ProcessName: "curl",
				Protocol:    "tcp",
				RemoteIP:    tt.remoteIP,
				RemotePort:  8080,
				State:       "ESTABLISHED",
			}

			monitor.analyzeConnection(conn)

			if tt.expectAnomaly && !conn.IsAnomalous {
				t.Error("Connection should be flagged as anomalous")
			}

			// Verify that private IPs don't trigger PRIVATE_IP_CONN due to exclusion
			for _, reason := range conn.AnomalousReasons {
				if reason == "PRIVATE_IP_CONN" {
					t.Errorf("Should not get PRIVATE_IP_CONN for %s (IPs are excluded), got %v", tt.remoteIP, conn.AnomalousReasons)
				}
			}
		})
	}
}

// TestAnalyzeConnection_ExternalPattern tests external connection detection
func TestAnalyzeConnection_ExternalPattern(t *testing.T) {
	config := DefaultConfig()
	config.AnomalousPatterns["external"] = true

	logger := log.New(os.Stdout, "[test] ", log.LstdFlags)
	monitor, err := NewConnectionMonitor(config, logger)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	tests := []struct {
		name          string
		remoteIP      string
		expectAnomaly bool
	}{
		{"Public IP Google", "8.8.8.8", true},
		{"Public IP Cloudflare", "1.1.1.1", true},
		{"Private IP", "192.168.1.1", false},
		{"Loopback", "127.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &Connection{
				ProcessName: "curl",
				Protocol:    "tcp",
				RemoteIP:    tt.remoteIP,
				RemotePort:  443,
				State:       "ESTABLISHED",
			}

			monitor.analyzeConnection(conn)

			if tt.expectAnomaly && !conn.IsAnomalous {
				t.Errorf("External connection to %s should be flagged as anomalous", tt.remoteIP)
			}

			if tt.expectAnomaly {
				found := false
				for _, reason := range conn.AnomalousReasons {
					if reason == "EXTERNAL_CONN" {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected EXTERNAL_CONN reason for %s, got %v", tt.remoteIP, conn.AnomalousReasons)
				}
			}
		})
	}
}

// TestAnalyzeConnection_HighPortsPattern tests high port detection
func TestAnalyzeConnection_HighPortsPattern(t *testing.T) {
	config := DefaultConfig()
	config.AnomalousPatterns["high_ports"] = true

	logger := log.New(os.Stdout, "[test] ", log.LstdFlags)
	monitor, err := NewConnectionMonitor(config, logger)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	tests := []struct {
		name          string
		remotePort    int
		expectAnomaly bool
	}{
		{"High port 50000", 50000, true},
		{"Ephemeral port 49152", 49152, false}, // Edge case: 49152 is not > 49152
		{"Ephemeral port 49153", 49153, true},
		{"Port 65535", 65535, true},
		{"Port 443", 443, false},
		{"Port 8080", 8080, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &Connection{
				ProcessName: "curl",
				Protocol:    "tcp",
				RemoteIP:    "8.8.8.8",
				RemotePort:  tt.remotePort,
				State:       "ESTABLISHED",
			}

			monitor.analyzeConnection(conn)

			if tt.expectAnomaly && !conn.IsAnomalous {
				t.Errorf("High port %d should be flagged as anomalous", tt.remotePort)
			}

			if tt.expectAnomaly {
				found := false
				for _, reason := range conn.AnomalousReasons {
					if len(reason) > 9 && reason[:9] == "HIGH_PORT" {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected HIGH_PORT reason for port %d, got %v", tt.remotePort, conn.AnomalousReasons)
				}
			}
		})
	}
}

// TestAnalyzeConnection_LowPortsPattern tests low/privileged port detection
func TestAnalyzeConnection_LowPortsPattern(t *testing.T) {
	config := DefaultConfig()
	config.AnomalousPatterns["low_ports"] = true

	logger := log.New(os.Stdout, "[test] ", log.LstdFlags)
	monitor, err := NewConnectionMonitor(config, logger)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	tests := []struct {
		name          string
		remotePort    int
		expectAnomaly bool
	}{
		{"Port 21 FTP", 21, true},
		{"Port 22 SSH", 22, true},
		{"Port 23 Telnet", 23, true},
		{"Port 25 SMTP", 25, true},
		{"Port 80 HTTP (excluded)", 80, false},
		{"Port 443 HTTPS (excluded)", 443, false},
		{"Port 1023", 1023, true},
		{"Port 1024", 1024, false},
		{"Port 0", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &Connection{
				ProcessName: "curl",
				Protocol:    "tcp",
				RemoteIP:    "8.8.8.8",
				RemotePort:  tt.remotePort,
				State:       "ESTABLISHED",
			}

			monitor.analyzeConnection(conn)

			if tt.expectAnomaly {
				found := false
				for _, reason := range conn.AnomalousReasons {
					if len(reason) > 8 && reason[:8] == "LOW_PORT" {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected LOW_PORT reason for port %d, got %v", tt.remotePort, conn.AnomalousReasons)
				}
			}
		})
	}
}

// TestAnalyzeConnection_SYN_SENT tests SYN_SENT state detection
func TestAnalyzeConnection_SYN_SENT(t *testing.T) {
	config := DefaultConfig()
	logger := log.New(os.Stdout, "[test] ", log.LstdFlags)
	monitor, err := NewConnectionMonitor(config, logger)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	tests := []struct {
		name          string
		remotePort    int
		expectAnomaly bool
	}{
		{"SYN_SENT to port 22", 22, true},
		{"SYN_SENT to port 8080", 8080, true},
		{"SYN_SENT to port 80", 80, false}, // HTTP is excluded
		{"SYN_SENT to port 443", 443, false}, // HTTPS is excluded
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &Connection{
				ProcessName: "curl",
				Protocol:    "tcp",
				RemoteIP:    "8.8.8.8",
				RemotePort:  tt.remotePort,
				State:       "SYN_SENT",
			}

			monitor.analyzeConnection(conn)

			if tt.expectAnomaly && !conn.IsAnomalous {
				t.Errorf("SYN_SENT to port %d should be flagged", tt.remotePort)
			}

			if tt.expectAnomaly {
				found := false
				for _, reason := range conn.AnomalousReasons {
					if len(reason) > 12 && reason[:12] == "TCP_SYN_SENT" {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected TCP_SYN_SENT reason for port %d, got %v", tt.remotePort, conn.AnomalousReasons)
				}
			}
		})
	}
}

// TestAnalyzeConnection_ProcessPortExclusion tests process-based port exclusions
func TestAnalyzeConnection_ProcessPortExclusion(t *testing.T) {
	config := DefaultConfig()
	config.AnomalousPatterns["high_ports"] = true

	// Configure exclusions
	config.ProcessPortExclusions = map[string][]PortRange{
		"chromium": {{Start: 49152, End: 65535}},
	}

	logger := log.New(os.Stdout, "[test] ", log.LstdFlags)
	monitor, err := NewConnectionMonitor(config, logger)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	tests := []struct {
		name          string
		processName   string
		remotePort    int
		expectAnomaly bool
	}{
		{"Chromium high port excluded", "chromium", 50000, false},
		{"Firefox high port not excluded", "firefox", 50000, true},
		{"Chromium port outside range", "chromium", 8080, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &Connection{
				ProcessName: tt.processName,
				Protocol:    "tcp",
				RemoteIP:    "8.8.8.8",
				RemotePort:  tt.remotePort,
				State:       "ESTABLISHED",
			}

			monitor.analyzeConnection(conn)

			hasHighPortAlert := false
			for _, reason := range conn.AnomalousReasons {
				if len(reason) > 9 && reason[:9] == "HIGH_PORT" {
					hasHighPortAlert = true
					break
				}
			}

			if tt.expectAnomaly && !hasHighPortAlert {
				t.Errorf("Expected HIGH_PORT alert for %s:%d", tt.processName, tt.remotePort)
			}
			if !tt.expectAnomaly && hasHighPortAlert {
				t.Errorf("Did not expect HIGH_PORT alert for %s:%d, got %v", tt.processName, tt.remotePort, conn.AnomalousReasons)
			}
		})
	}
}

// TestAnalyzeConnection_RemoteIPExclusion tests remote IP exclusions
func TestAnalyzeConnection_RemoteIPExclusion(t *testing.T) {
	config := DefaultConfig()
	config.AnomalousPatterns["high_ports"] = true
	config.AllowedRemoteIPs = map[string]bool{
		"203.0.113.42": true,
	}

	logger := log.New(os.Stdout, "[test] ", log.LstdFlags)
	monitor, err := NewConnectionMonitor(config, logger)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	tests := []struct {
		name       string
		remoteIP   string
		shouldSkip bool
	}{
		{"Allowed IP", "203.0.113.42", true},
		{"Non-allowed IP", "198.51.100.1", false},
		{"Private IP (built-in exclusion)", "192.168.1.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &Connection{
				ProcessName: "curl",
				Protocol:    "tcp",
				RemoteIP:    tt.remoteIP,
				RemotePort:  50000,
				State:       "ESTABLISHED",
			}

			monitor.analyzeConnection(conn)

			hasHighPortAlert := false
			for _, reason := range conn.AnomalousReasons {
				if len(reason) > 9 && reason[:9] == "HIGH_PORT" {
					hasHighPortAlert = true
					break
				}
			}

			if tt.shouldSkip && hasHighPortAlert {
				t.Errorf("Should not alert on excluded IP %s, got %v", tt.remoteIP, conn.AnomalousReasons)
			}
			if !tt.shouldSkip && !hasHighPortAlert {
				t.Errorf("Should alert on non-excluded IP %s", tt.remoteIP)
			}
		})
	}
}

// TestNewConnectionMonitor tests monitor creation
func TestNewConnectionMonitor(t *testing.T) {
	config := DefaultConfig()
	logger := log.New(os.Stdout, "[test] ", log.LstdFlags)

	monitor, err := NewConnectionMonitor(config, logger)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	if monitor == nil {
		t.Fatal("Monitor should not be nil")
	}

	if monitor.config != config {
		t.Error("Monitor config not set correctly")
	}

	if monitor.prevConns == nil {
		t.Error("prevConns should be initialized")
	}

	if monitor.alertHistory == nil {
		t.Error("alertHistory should be initialized")
	}

	if monitor.notificationHistory == nil {
		t.Error("notificationHistory should be initialized")
	}
}

// TestUpdateConfig tests configuration updates
func TestUpdateConfig(t *testing.T) {
	config := DefaultConfig()
	logger := log.New(os.Stdout, "[test] ", log.LstdFlags)

	monitor, err := NewConnectionMonitor(config, logger)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	// Create new config
	newConfig := DefaultConfig()
	newConfig.AnomalousPatterns["udp"] = true
	newConfig.StandardPortsUDP[51820] = true

	// Update config
	monitor.UpdateConfig(newConfig)

	// Verify config was updated
	monitor.configMu.RLock()
	defer monitor.configMu.RUnlock()

	if !monitor.config.AnomalousPatterns["udp"] {
		t.Error("Config not updated: udp pattern should be enabled")
	}

	if !monitor.config.StandardPortsUDP[51820] {
		t.Error("Config not updated: port 51820 should be in StandardPortsUDP")
	}
}

// TestGetProtocolString tests protocol string conversion
func TestGetProtocolString(t *testing.T) {
	tests := []struct {
		sockType uint32
		expected string
	}{
		{1, "tcp"},
		{2, "udp"},
		{3, "proto_3"},
		{0, "proto_0"},
		{99, "proto_99"},
	}

	for _, tt := range tests {
		result := getProtocolString(tt.sockType)
		if result != tt.expected {
			t.Errorf("getProtocolString(%d) = %q, expected %q", tt.sockType, result, tt.expected)
		}
	}
}

// TestAnalyzeConnection_MultipleReasons tests connections that trigger multiple alert reasons
func TestAnalyzeConnection_MultipleReasons(t *testing.T) {
	config := DefaultConfig()
	config.AnomalousPatterns["ssh"] = true
	config.AnomalousPatterns["external"] = true
	config.AnomalousPatterns["low_ports"] = true

	logger := log.New(os.Stdout, "[test] ", log.LstdFlags)
	monitor, err := NewConnectionMonitor(config, logger)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	conn := &Connection{
		ProcessName: "ssh",
		Protocol:    "tcp",
		RemoteIP:    "8.8.8.8", // Public IP
		RemotePort:  22,        // SSH port, also a low port
		State:       "ESTABLISHED",
	}

	monitor.analyzeConnection(conn)

	if !conn.IsAnomalous {
		t.Fatal("Connection should be flagged as anomalous")
	}

	// Should have multiple reasons
	expectedReasons := []string{"SSH_OUTBOUND", "EXTERNAL_CONN", "LOW_PORT"}
	for _, expected := range expectedReasons {
		found := false
		for _, reason := range conn.AnomalousReasons {
			if reason == expected || (expected == "LOW_PORT" && len(reason) > 8 && reason[:8] == "LOW_PORT") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected reason %q in %v", expected, conn.AnomalousReasons)
		}
	}
}