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

// ParseIP extracts IP from address endpoint (may include port after colon)
func ParseIP(addr string) string {
	parts := strings.Split(addr, ":")
	return parts[0]
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
