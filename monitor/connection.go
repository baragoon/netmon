package monitor

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Connection represents a network connection
type Connection struct {
	PID        uint32
	ProcessName string
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
	Protocol   string
	State      string
	IsAnomalous bool
	AnomalousReasons []string
}

// ParseIP returns the IP address, handling both IPv4 and IPv6
func ParseIP(addr string) string {
	// gopsutil already provides IP separately from port, so just return as-is
	// This preserves IPv6 addresses which contain colons
	return addr
}

// ParsePort extracts port from address endpoint (after colon)
func ParsePort(addr string) int {
	parts := strings.Split(addr, ":")
	if len(parts) > 1 {
		if port, err := strconv.Atoi(parts[1]); err == nil {
			return port
		}
	}
	return 0
}

// IsPrivateIP checks if IP is in private range
func IsPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// IPv4 private ranges
	return parsedIP.IsPrivate() || parsedIP.IsLoopback() || parsedIP.IsLinkLocalUnicast()
}

// IsPublicIP checks if IP is public
func IsPublicIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	return !parsedIP.IsPrivate() && !parsedIP.IsLoopback() && !parsedIP.IsLinkLocalUnicast() && !parsedIP.IsUnspecified()
}

// String returns a readable string representation
func (c *Connection) String() string {
	return fmt.Sprintf("%s (%d) -> %s:%d [%s %s]",
		c.ProcessName,
		c.PID,
		c.RemoteIP,
		c.RemotePort,
		c.Protocol,
		c.State,
	)
}

// DetailedString returns detailed information including anomalies
func (c *Connection) DetailedString() string {
	result := c.String()
	if c.IsAnomalous && len(c.AnomalousReasons) > 0 {
		result += fmt.Sprintf(" [ALERT: %s]", strings.Join(c.AnomalousReasons, ", "))
	}
	return result
}

// remoteAddressKey creates a unique key based on remote IP and port only
// Used for deduplicating notifications to avoid spam from the same address
func (c *Connection) remoteAddressKey() string {
	return fmt.Sprintf("%s:%d", c.RemoteIP, c.RemotePort)
}

// notificationCooldownKey creates a key for notification cooldown deduplication.
// For LISTEN sockets bound to unspecified addresses (0.0.0.0/::), deduplicate by
// local port so different LISTEN ports are tracked independently.
func (c *Connection) notificationCooldownKey() string {
	if c.State == "LISTEN" && (c.RemoteIP == "0.0.0.0" || c.RemoteIP == "::" || c.RemoteIP == "") {
		return fmt.Sprintf("LISTEN_PORT_%d", c.LocalPort)
	}

	return c.remoteAddressKey()
}
