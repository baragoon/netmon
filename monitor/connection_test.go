package monitor

import (
	"net"
	"strings"
	"testing"
)

// TestParseIP tests IP address parsing
func TestParseIP(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected string
	}{
		{"IPv4 address", "192.168.1.1", "192.168.1.1"},
		{"IPv6 address", "2001:db8::1", "2001:db8::1"},
		{"Localhost", "127.0.0.1", "127.0.0.1"},
		{"IPv6 localhost", "::1", "::1"},
		{"Empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseIP(tt.addr)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestParsePort tests port extraction from address
func TestParsePort(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected int
	}{
		{"Standard format", "192.168.1.1:8080", 8080},
		{"SSH port", "192.168.1.1:22", 22},
		{"HTTPS port", "192.168.1.1:443", 443},
		{"High port", "192.168.1.1:65535", 65535},
		{"No port", "192.168.1.1", 0},
		{"Invalid port", "192.168.1.1:abc", 0},
		{"Empty string", "", 0},
		{"IPv6 with port", "[2001:db8::1]:8080", 0}, // Note: this is a known limitation
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePort(tt.addr)
			if result != tt.expected {
				t.Errorf("Expected %d, got %d", tt.expected, result)
			}
		})
	}
}

// TestIsPrivateIP tests private IP detection
func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Private IPv4 ranges
		{"Private 10.0.0.0/8", "10.0.0.1", true},
		{"Private 10.255.255.254", "10.255.255.254", true},
		{"Private 172.16.0.0/12", "172.16.0.1", true},
		{"Private 172.31.255.254", "172.31.255.254", true},
		{"Private 192.168.0.0/16", "192.168.1.1", true},
		{"Private 192.168.255.254", "192.168.255.254", true},

		// Loopback addresses
		{"Loopback 127.0.0.1", "127.0.0.1", true},
		{"Loopback 127.0.0.2", "127.0.0.2", true},
		{"IPv6 loopback", "::1", true},

		// Link-local addresses
		{"Link-local IPv4", "169.254.1.1", true},
		{"Link-local IPv6", "fe80::1", true},
		{"Link-local IPv6 full", "fe80:0000:0000:0000:0000:0000:0000:0001", true},

		// Public IPs (should be false)
		{"Public Google DNS", "8.8.8.8", false},
		{"Public Cloudflare DNS", "1.1.1.1", false},
		{"Public IP", "203.0.113.1", false},

		// Edge cases
		{"Empty string", "", false},
		{"Invalid IP", "not-an-ip", false},
		{"Invalid format", "256.256.256.256", false},

		// IPv6 private addresses
		{"IPv6 ULA", "fc00::1", true},
		{"IPv6 ULA fd", "fd00::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPrivateIP(tt.ip)
			if result != tt.expected {
				t.Errorf("Expected %v for IP %q, got %v", tt.expected, tt.ip, result)
			}
		})
	}
}

// TestIsPublicIP tests public IP detection
func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Public IPs
		{"Public Google DNS", "8.8.8.8", true},
		{"Public Cloudflare", "1.1.1.1", true},
		{"Public IP", "203.0.113.1", true},
		{"Public IPv6", "2001:4860:4860::8888", true},

		// Private IPs (should be false)
		{"Private 10.x.x.x", "10.0.0.1", false},
		{"Private 192.168.x.x", "192.168.1.1", false},
		{"Private 172.16.x.x", "172.16.0.1", false},

		// Loopback (should be false)
		{"Loopback", "127.0.0.1", false},
		{"IPv6 loopback", "::1", false},

		// Link-local (should be false)
		{"Link-local", "169.254.1.1", false},
		{"IPv6 link-local", "fe80::1", false},

		// Unspecified (should be false)
		{"Unspecified IPv4", "0.0.0.0", false},
		{"Unspecified IPv6", "::", false},

		// Invalid
		{"Invalid IP", "not-an-ip", false},
		{"Empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPublicIP(tt.ip)
			if result != tt.expected {
				t.Errorf("Expected %v for IP %q, got %v", tt.expected, tt.ip, result)
			}
		})
	}
}

// TestConnectionString tests the String method of Connection
func TestConnectionString(t *testing.T) {
	conn := &Connection{
		ProcessName: "curl",
		PID:         1234,
		RemoteIP:    "192.168.1.1",
		RemotePort:  443,
		Protocol:    "tcp",
		State:       "ESTABLISHED",
	}

	result := conn.String()
	expected := "curl (1234) -> 192.168.1.1:443 [tcp ESTABLISHED]"

	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

// TestConnectionDetailedString tests the DetailedString method
func TestConnectionDetailedString(t *testing.T) {
	tests := []struct {
		name            string
		conn            *Connection
		expectedContain []string
	}{
		{
			name: "Normal connection without anomalies",
			conn: &Connection{
				ProcessName: "curl",
				PID:         1234,
				RemoteIP:    "192.168.1.1",
				RemotePort:  443,
				Protocol:    "tcp",
				State:       "ESTABLISHED",
				IsAnomalous: false,
			},
			expectedContain: []string{"curl", "1234", "192.168.1.1:443", "tcp", "ESTABLISHED"},
		},
		{
			name: "Anomalous SSH connection",
			conn: &Connection{
				ProcessName:      "ssh",
				PID:              5678,
				RemoteIP:         "203.0.113.42",
				RemotePort:       22,
				Protocol:         "tcp",
				State:            "ESTABLISHED",
				IsAnomalous:      true,
				AnomalousReasons: []string{"SSH_OUTBOUND"},
			},
			expectedContain: []string{"ssh", "5678", "203.0.113.42:22", "ALERT", "SSH_OUTBOUND"},
		},
		{
			name: "Multiple anomaly reasons",
			conn: &Connection{
				ProcessName:      "malware",
				PID:              9999,
				RemoteIP:         "198.51.100.1",
				RemotePort:       8080,
				Protocol:         "tcp",
				State:            "SYN_SENT",
				IsAnomalous:      true,
				AnomalousReasons: []string{"HIGH_PORT_8080", "EXTERNAL_CONN"},
			},
			expectedContain: []string{"malware", "9999", "198.51.100.1:8080", "ALERT", "HIGH_PORT_8080", "EXTERNAL_CONN"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.conn.DetailedString()
			for _, expected := range tt.expectedContain {
				if !strings.Contains(result, expected) {
					t.Errorf("Expected result to contain %q, got %q", expected, result)
				}
			}
		})
	}
}

// TestRemoteAddressKey tests the remoteAddressKey method
func TestRemoteAddressKey(t *testing.T) {
	conn := &Connection{
		RemoteIP:   "192.168.1.1",
		RemotePort: 443,
	}

	result := conn.remoteAddressKey()
	expected := "192.168.1.1:443"

	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

// TestBypassNotificationCooldown tests LISTEN socket cooldown bypass logic
func TestBypassNotificationCooldown(t *testing.T) {
	tests := []struct {
		name     string
		conn     *Connection
		expected bool
	}{
		{
			name: "LISTEN on 0.0.0.0",
			conn: &Connection{
				State:    "LISTEN",
				RemoteIP: "0.0.0.0",
			},
			expected: true,
		},
		{
			name: "LISTEN on ::",
			conn: &Connection{
				State:    "LISTEN",
				RemoteIP: "::",
			},
			expected: true,
		},
		{
			name: "LISTEN on empty",
			conn: &Connection{
				State:    "LISTEN",
				RemoteIP: "",
			},
			expected: true,
		},
		{
			name: "LISTEN on specific IP",
			conn: &Connection{
				State:    "LISTEN",
				RemoteIP: "192.168.1.1",
			},
			expected: false,
		},
		{
			name: "ESTABLISHED connection",
			conn: &Connection{
				State:    "ESTABLISHED",
				RemoteIP: "0.0.0.0",
			},
			expected: false,
		},
		{
			name: "SYN_SENT connection",
			conn: &Connection{
				State:    "SYN_SENT",
				RemoteIP: "::",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.conn.bypassNotificationCooldown()
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestNotificationCooldownKey tests notification cooldown key generation
func TestNotificationCooldownKey(t *testing.T) {
	tests := []struct {
		name     string
		conn     *Connection
		expected string
	}{
		{
			name: "LISTEN on 0.0.0.0",
			conn: &Connection{
				State:     "LISTEN",
				RemoteIP:  "0.0.0.0",
				LocalPort: 8080,
			},
			expected: "LISTEN_PORT_8080",
		},
		{
			name: "LISTEN on ::",
			conn: &Connection{
				State:     "LISTEN",
				RemoteIP:  "::",
				LocalPort: 443,
			},
			expected: "LISTEN_PORT_443",
		},
		{
			name: "LISTEN on empty",
			conn: &Connection{
				State:     "LISTEN",
				RemoteIP:  "",
				LocalPort: 22,
			},
			expected: "LISTEN_PORT_22",
		},
		{
			name: "ESTABLISHED connection",
			conn: &Connection{
				State:      "ESTABLISHED",
				RemoteIP:   "192.168.1.1",
				RemotePort: 443,
			},
			expected: "192.168.1.1:443",
		},
		{
			name: "SYN_SENT connection",
			conn: &Connection{
				State:      "SYN_SENT",
				RemoteIP:   "203.0.113.42",
				RemotePort: 22,
			},
			expected: "203.0.113.42:22",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.conn.notificationCooldownKey()
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestGetServiceName tests service name lookup
func TestGetServiceName(t *testing.T) {
	// Initialize the service cache
	initServiceCache()

	tests := []struct {
		name     string
		port     int
		expected string // Can be empty if service not found
	}{
		{"HTTP port", 80, "http"},
		{"HTTPS port", 443, "https"},
		{"SSH port", 22, "ssh"},
		{"DNS port", 53, "domain"},
		{"FTP port", 21, "ftp"},
		{"Telnet port", 23, "telnet"},
		{"SMTP port", 25, "smtp"},
		{"Unknown high port", 54321, ""},
		{"Port 0", 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetServiceName(tt.port)
			// Service names can vary by system, so we just check if we get a string
			// For well-known ports, we expect a non-empty result on most systems
			if tt.port == 80 || tt.port == 443 || tt.port == 22 {
				if result == "" {
					t.Errorf("Expected service name for port %d, got empty string", tt.port)
				}
			}
			// For unknown ports, we expect empty string
			if tt.port == 54321 || tt.port == 0 {
				if result != "" {
					t.Logf("Port %d resolved to %q (system-specific)", tt.port, result)
				}
			}
		})
	}
}

// TestFormatPort tests port formatting with service names
func TestFormatPort(t *testing.T) {
	// Initialize the service cache
	initServiceCache()

	tests := []struct {
		name     string
		port     int
		mustHave string // String that must be in result
	}{
		{"Port 0 shows asterisk", 0, "*"},
		{"HTTP port shows number", 80, "80"},
		{"HTTPS port shows number", 443, "443"},
		{"SSH port shows number", 22, "22"},
		{"Unknown port shows number", 54321, "54321"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatPort(tt.port)
			if !strings.Contains(result, tt.mustHave) {
				t.Errorf("Expected result to contain %q, got %q", tt.mustHave, result)
			}
		})
	}
}

// TestConnectionKey tests connection key generation
func TestConnectionKey(t *testing.T) {
	conn := &Connection{
		PID:        1234,
		RemoteIP:   "192.168.1.1",
		RemotePort: 443,
		LocalIP:    "10.0.0.1",
		LocalPort:  54321,
	}

	result := conn.connectionKey()
	expected := "1234_192.168.1.1_443_10.0.0.1_54321"

	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

// TestConnectionKey_Uniqueness tests that different connections get different keys
func TestConnectionKey_Uniqueness(t *testing.T) {
	conn1 := &Connection{
		PID:        1234,
		RemoteIP:   "192.168.1.1",
		RemotePort: 443,
		LocalIP:    "10.0.0.1",
		LocalPort:  54321,
	}

	conn2 := &Connection{
		PID:        1234,
		RemoteIP:   "192.168.1.1",
		RemotePort: 443,
		LocalIP:    "10.0.0.1",
		LocalPort:  54322, // Different local port
	}

	key1 := conn1.connectionKey()
	key2 := conn2.connectionKey()

	if key1 == key2 {
		t.Errorf("Expected different keys for different connections, got same key: %q", key1)
	}
}

// TestIsPrivateIP_IPv6 tests IPv6 private address detection specifically
func TestIsPrivateIP_IPv6(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"IPv6 loopback", "::1", true},
		{"IPv6 ULA fc00", "fc00::1", true},
		{"IPv6 ULA fd00", "fd00:1234::1", true},
		{"IPv6 link-local", "fe80::1", true},
		// Zone IDs in IPv6 addresses are not standard format for net.ParseIP
		// {"IPv6 link-local with zone", "fe80::1%eth0", true},
		{"IPv6 public", "2001:4860:4860::8888", false},
		{"IPv6 documentation", "2001:db8::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPrivateIP(tt.ip)
			if result != tt.expected {
				t.Errorf("Expected %v for IP %q, got %v", tt.expected, tt.ip, result)
			}
		})
	}
}

// TestIsPublicIP_EdgeCases tests edge cases for public IP detection
func TestIsPublicIP_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Note: Go's net.IP methods classify these addresses as follows:
		// - Broadcast (255.255.255.255) is not private/loopback/link-local/unspecified, so it's "public"
		// - Multicast addresses are also not private/loopback, so they're "public"
		{"Broadcast", "255.255.255.255", true}, // Not marked as special by Go, so appears "public"
		{"Multicast", "224.0.0.1", true}, // Multicast is technically public (not private/loopback)
		{"Reserved", "240.0.0.1", true}, // Reserved range but not marked as private by Go
		{"IPv6 multicast", "ff02::1", true}, // Multicast is not private
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPublicIP(tt.ip)
			if result != tt.expected {
				t.Errorf("Expected %v for IP %q, got %v (IsPrivate=%v, IsLoopback=%v, IsUnspecified=%v)",
					tt.expected, tt.ip, result,
					func() bool { ip := parseTestIP(tt.ip); return ip != nil && ip.IsPrivate() }(),
					func() bool { ip := parseTestIP(tt.ip); return ip != nil && ip.IsLoopback() }(),
					func() bool { ip := parseTestIP(tt.ip); return ip != nil && ip.IsUnspecified() }())
			}
		})
	}
}

// parseTestIP is a helper for testing
func parseTestIP(s string) *net.IP {
	ip := net.ParseIP(s)
	return &ip
}