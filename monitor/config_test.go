package monitor

import (
	"net"
	"os"
	"testing"
	"time"
)

// TestDefaultConfig verifies the default configuration has correct TCP and UDP standard ports
func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	// Verify interval
	if config.Interval != 5*time.Second {
		t.Errorf("Expected interval 5s, got %v", config.Interval)
	}

	// Verify ListenAlertCooldown
	if config.ListenAlertCooldown != 1*time.Minute {
		t.Errorf("Expected ListenAlertCooldown 1m, got %v", config.ListenAlertCooldown)
	}

	// Verify default TCP standard ports
	expectedTCPPorts := []int{80, 443, 53}
	for _, port := range expectedTCPPorts {
		if !config.StandardPortsTCP[port] {
			t.Errorf("Expected TCP port %d to be in StandardPortsTCP", port)
		}
	}
	if len(config.StandardPortsTCP) != len(expectedTCPPorts) {
		t.Errorf("Expected %d TCP standard ports, got %d", len(expectedTCPPorts), len(config.StandardPortsTCP))
	}

	// Verify default UDP standard ports
	expectedUDPPorts := []int{53, 123, 67, 68}
	for _, port := range expectedUDPPorts {
		if !config.StandardPortsUDP[port] {
			t.Errorf("Expected UDP port %d to be in StandardPortsUDP", port)
		}
	}
	if len(config.StandardPortsUDP) != len(expectedUDPPorts) {
		t.Errorf("Expected %d UDP standard ports, got %d", len(expectedUDPPorts), len(config.StandardPortsUDP))
	}

	// Verify anomalous patterns defaults
	if !config.AnomalousPatterns["ssh"] {
		t.Error("Expected ssh pattern to be enabled by default")
	}
	if !config.AnomalousPatterns["telnet"] {
		t.Error("Expected telnet pattern to be enabled by default")
	}
	if config.AnomalousPatterns["udp"] {
		t.Error("Expected udp pattern to be disabled by default")
	}
	if config.AnomalousPatterns["private_ip"] {
		t.Error("Expected private_ip pattern to be disabled by default")
	}
}

// TestLoadFromFile_StandardPorts tests loading separate TCP and UDP standard ports from config file
func TestLoadFromFile_StandardPorts(t *testing.T) {
	// Create a temporary config file
	configContent := `{
		"interval": "10s",
		"listen_alert_cooldown": "2m",
		"standard_ports_tcp": [80, 443, 3306, 5432],
		"standard_ports_udp": [53, 123, 51820],
		"anomalous_patterns": ["ssh", "telnet", "udp"]
	}`

	tmpfile, err := os.CreateTemp("", "config_test_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(configContent)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	config := DefaultConfig()
	if err := config.LoadFromFile(tmpfile.Name()); err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify interval was updated
	if config.Interval != 10*time.Second {
		t.Errorf("Expected interval 10s, got %v", config.Interval)
	}

	// Verify ListenAlertCooldown was updated
	if config.ListenAlertCooldown != 2*time.Minute {
		t.Errorf("Expected ListenAlertCooldown 2m, got %v", config.ListenAlertCooldown)
	}

	// Verify TCP standard ports were loaded correctly
	expectedTCPPorts := []int{80, 443, 3306, 5432}
	if len(config.StandardPortsTCP) != len(expectedTCPPorts) {
		t.Errorf("Expected %d TCP ports, got %d", len(expectedTCPPorts), len(config.StandardPortsTCP))
	}
	for _, port := range expectedTCPPorts {
		if !config.StandardPortsTCP[port] {
			t.Errorf("Expected TCP port %d to be in StandardPortsTCP", port)
		}
	}

	// Verify UDP standard ports were loaded correctly
	expectedUDPPorts := []int{53, 123, 51820}
	if len(config.StandardPortsUDP) != len(expectedUDPPorts) {
		t.Errorf("Expected %d UDP ports, got %d", len(expectedUDPPorts), len(config.StandardPortsUDP))
	}
	for _, port := range expectedUDPPorts {
		if !config.StandardPortsUDP[port] {
			t.Errorf("Expected UDP port %d to be in StandardPortsUDP", port)
		}
	}

	// Verify anomalous patterns
	if !config.AnomalousPatterns["udp"] {
		t.Error("Expected udp pattern to be enabled")
	}
}

// TestLoadFromFile_EmptyStandardPorts tests that empty port arrays don't override defaults
func TestLoadFromFile_EmptyStandardPorts(t *testing.T) {
	configContent := `{
		"anomalous_patterns": ["ssh"]
	}`

	tmpfile, err := os.CreateTemp("", "config_test_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(configContent)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	config := DefaultConfig()
	originalTCPPortCount := len(config.StandardPortsTCP)
	originalUDPPortCount := len(config.StandardPortsUDP)

	if err := config.LoadFromFile(tmpfile.Name()); err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify that default ports are still present when config doesn't specify them
	if len(config.StandardPortsTCP) != originalTCPPortCount {
		t.Errorf("Expected TCP ports to remain at %d, got %d", originalTCPPortCount, len(config.StandardPortsTCP))
	}
	if len(config.StandardPortsUDP) != originalUDPPortCount {
		t.Errorf("Expected UDP ports to remain at %d, got %d", originalUDPPortCount, len(config.StandardPortsUDP))
	}
}

// TestParsePortRangeSpec tests parsing of port range specifications
func TestParsePortRangeSpec(t *testing.T) {
	tests := []struct {
		name        string
		spec        string
		wantStart   int
		wantEnd     int
		expectError bool
	}{
		{"Single port", "443", 443, 443, false},
		{"Port range", "49152-65535", 49152, 65535, false},
		{"Port range with spaces", " 8000 - 9000 ", 8000, 9000, false},
		{"Single port with spaces", " 80 ", 80, 80, false},
		{"Empty spec", "", 0, 0, true},
		{"Invalid range format", "8000-9000-10000", 0, 0, true},
		{"Invalid start port", "abc-9000", 0, 0, true},
		{"Invalid end port", "8000-xyz", 0, 0, true},
		{"Start greater than end", "9000-8000", 0, 0, true},
		{"Negative port", "-1", 0, 0, true},
		{"Port too high", "70000", 0, 0, true},
		{"Range exceeds max", "60000-70000", 0, 0, true},
		{"Zero port", "0", 0, 0, false},
		{"Max valid port", "65535", 65535, 65535, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parsePortRangeSpec(tt.spec)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for spec %q, got nil", tt.spec)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for spec %q: %v", tt.spec, err)
				}
				if result.Start != tt.wantStart {
					t.Errorf("Expected start %d, got %d", tt.wantStart, result.Start)
				}
				if result.End != tt.wantEnd {
					t.Errorf("Expected end %d, got %d", tt.wantEnd, result.End)
				}
			}
		})
	}
}

// TestIsProcessPortExcluded tests process port exclusion functionality
func TestIsProcessPortExcluded(t *testing.T) {
	config := DefaultConfig()
	config.ProcessPortExclusions = map[string][]PortRange{
		"chromium": {
			{Start: 49152, End: 65535},
			{Start: 443, End: 443},
		},
		"forgejo-runner": {
			{Start: 32768, End: 65535},
		},
	}

	tests := []struct {
		name        string
		processName string
		port        int
		expected    bool
	}{
		{"Chromium high port in range", "chromium", 50000, true},
		{"Chromium port 443", "chromium", 443, true},
		{"Chromium port not in range", "chromium", 8080, false},
		{"Chromium case insensitive", "Chromium", 50000, true},
		{"Chromium with spaces", " chromium ", 50000, true},
		{"Forgejo runner in range", "forgejo-runner", 40000, true},
		{"Forgejo runner edge start", "forgejo-runner", 32768, true},
		{"Forgejo runner edge end", "forgejo-runner", 65535, true},
		{"Forgejo runner below range", "forgejo-runner", 30000, false},
		{"Unknown process", "firefox", 50000, false},
		{"Negative port", "chromium", -1, false},
		{"Empty process name", "", 50000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.IsProcessPortExcluded(tt.processName, tt.port)
			if result != tt.expected {
				t.Errorf("Expected %v for process %q port %d, got %v", tt.expected, tt.processName, tt.port, result)
			}
		})
	}
}

// TestIsRemoteIPExcluded tests IP exclusion logic
func TestIsRemoteIPExcluded(t *testing.T) {
	config := DefaultConfig()

	// Add some custom allowed IPs
	config.AllowedRemoteIPs = map[string]bool{
		"192.0.2.1": true,
	}

	// Add a CIDR range
	_, cidr, _ := net.ParseCIDR("203.0.113.0/24")
	config.AllowedRemoteCIDRs = []*net.IPNet{cidr}

	tests := []struct {
		name     string
		remoteIP string
		expected bool
	}{
		// Loopback addresses
		{"IPv4 loopback", "127.0.0.1", true},
		{"IPv6 loopback", "::1", true},

		// Private IPv4 addresses
		{"Private 10.x.x.x", "10.0.0.1", true},
		{"Private 192.168.x.x", "192.168.1.1", true},
		{"Private 172.16.x.x", "172.16.0.1", true},

		// Link-local addresses
		{"IPv4 link-local", "169.254.1.1", true},
		{"IPv6 link-local", "fe80::1", true},

		// Custom allowed IP
		{"Custom allowed IP", "192.0.2.1", true},

		// Custom allowed CIDR
		{"Custom CIDR start", "203.0.113.1", true},
		{"Custom CIDR middle", "203.0.113.100", true},
		{"Custom CIDR end", "203.0.113.254", true},
		{"Outside custom CIDR", "203.0.114.1", false},

		// Public IPs that should not be excluded
		{"Public IP Google DNS", "8.8.8.8", false},
		{"Public IP Cloudflare", "1.1.1.1", false},

		// Invalid IPs
		{"Invalid IP", "not-an-ip", false},
		{"Empty IP", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.IsRemoteIPExcluded(tt.remoteIP)
			if result != tt.expected {
				t.Errorf("Expected %v for IP %q, got %v", tt.expected, tt.remoteIP, result)
			}
		})
	}
}

// TestLoadFromFile_ProcessPortExclusions tests loading process port exclusions
func TestLoadFromFile_ProcessPortExclusions(t *testing.T) {
	configContent := `{
		"process_port_exclusions": {
			"chromium": ["49152-65535", "443"],
			"firefox": ["8080"],
			"invalid-process": ["abc-def"]
		}
	}`

	tmpfile, err := os.CreateTemp("", "config_test_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(configContent)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	config := DefaultConfig()
	if err := config.LoadFromFile(tmpfile.Name()); err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify chromium has 2 ranges
	chromiumRanges := config.ProcessPortExclusions["chromium"]
	if len(chromiumRanges) != 2 {
		t.Errorf("Expected 2 ranges for chromium, got %d", len(chromiumRanges))
	}

	// Verify firefox has 1 range
	firefoxRanges := config.ProcessPortExclusions["firefox"]
	if len(firefoxRanges) != 1 {
		t.Errorf("Expected 1 range for firefox, got %d", len(firefoxRanges))
	}
	if firefoxRanges[0].Start != 8080 || firefoxRanges[0].End != 8080 {
		t.Errorf("Expected firefox range [8080-8080], got [%d-%d]", firefoxRanges[0].Start, firefoxRanges[0].End)
	}

	// Verify invalid process was ignored or has no ranges
	invalidRanges := config.ProcessPortExclusions["invalid-process"]
	if len(invalidRanges) != 0 {
		t.Errorf("Expected 0 ranges for invalid-process, got %d", len(invalidRanges))
	}
}

// TestLoadFromFile_AllowedRemoteIPs tests loading allowed remote IPs and CIDRs
func TestLoadFromFile_AllowedRemoteIPs(t *testing.T) {
	configContent := `{
		"allowed_remote_ips": [
			"192.0.2.1",
			"198.51.100.50",
			"203.0.113.0/24",
			"2001:db8::/32",
			"invalid-ip",
			""
		]
	}`

	tmpfile, err := os.CreateTemp("", "config_test_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(configContent)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	config := DefaultConfig()
	if err := config.LoadFromFile(tmpfile.Name()); err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify individual IPs
	if !config.AllowedRemoteIPs["192.0.2.1"] {
		t.Error("Expected 192.0.2.1 to be in AllowedRemoteIPs")
	}
	if !config.AllowedRemoteIPs["198.51.100.50"] {
		t.Error("Expected 198.51.100.50 to be in AllowedRemoteIPs")
	}

	// Verify CIDRs were parsed (should be 2: one IPv4, one IPv6)
	if len(config.AllowedRemoteCIDRs) != 2 {
		t.Errorf("Expected 2 CIDRs, got %d", len(config.AllowedRemoteCIDRs))
	}

	// Verify invalid entries were ignored
	if config.AllowedRemoteIPs["invalid-ip"] {
		t.Error("Expected invalid-ip to be ignored")
	}
	if config.AllowedRemoteIPs[""] {
		t.Error("Expected empty string to be ignored")
	}
}

// TestLoadFromFile_InvalidJSON tests handling of invalid JSON
func TestLoadFromFile_InvalidJSON(t *testing.T) {
	configContent := `{invalid json`

	tmpfile, err := os.CreateTemp("", "config_test_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(configContent)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	config := DefaultConfig()
	err = config.LoadFromFile(tmpfile.Name())
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}

// TestLoadFromFile_NonexistentFile tests handling of missing config file
func TestLoadFromFile_NonexistentFile(t *testing.T) {
	config := DefaultConfig()
	err := config.LoadFromFile("/nonexistent/config.json")
	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}
}

// TestIsRemoteIPHighPortExcluded tests backward compatibility function
func TestIsRemoteIPHighPortExcluded(t *testing.T) {
	config := DefaultConfig()

	// This function should delegate to IsRemoteIPExcluded
	result1 := config.IsRemoteIPHighPortExcluded("127.0.0.1")
	result2 := config.IsRemoteIPExcluded("127.0.0.1")

	if result1 != result2 {
		t.Error("IsRemoteIPHighPortExcluded should behave identically to IsRemoteIPExcluded")
	}
}

// TestConfigConcurrentAccess tests thread-safe configuration access
func TestIsProcessPortExcluded_NilConfig(t *testing.T) {
	var config *Config
	result := config.IsProcessPortExcluded("chromium", 50000)
	if result {
		t.Error("Expected false for nil config")
	}
}

// TestIsRemoteIPExcluded_NilConfig tests nil config handling
func TestIsRemoteIPExcluded_NilConfig(t *testing.T) {
	var config *Config
	result := config.IsRemoteIPExcluded("8.8.8.8")
	if result {
		t.Error("Expected false for nil config with public IP")
	}

	// But loopback should still be excluded due to built-in check
	result = config.IsRemoteIPExcluded("127.0.0.1")
	if !result {
		t.Error("Expected true for loopback even with nil config")
	}
}