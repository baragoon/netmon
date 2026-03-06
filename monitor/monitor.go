package monitor

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// ConnectionMonitor monitors network connections
type ConnectionMonitor struct {
	configMu            sync.RWMutex
	config              *Config
	logger              *log.Logger
	prevConns           map[string]*Connection
	alertHistory        map[string]time.Time
	notificationHistory map[string]time.Time
	notifier            *NotificationManager
}

// NewConnectionMonitor creates a new monitor
func NewConnectionMonitor(config *Config, logger *log.Logger) (*ConnectionMonitor, error) {
	notifier := NewNotificationManager(config.Notifications)
	if notifier != nil {
		logger.Printf("Notification manager initialized with %d provider(s)", len(notifier.notifiers))
	} else if config.Notifications != nil && config.Notifications.Enabled {
		logger.Printf("Warning: Notifications enabled but no notification manager created")
	}

	return &ConnectionMonitor{
		config:              config,
		logger:              logger,
		prevConns:           make(map[string]*Connection),
		alertHistory:        make(map[string]time.Time),
		notificationHistory: make(map[string]time.Time),
		notifier:            notifier,
	}, nil
}

// UpdateConfig safely updates the monitor configuration
func (m *ConnectionMonitor) UpdateConfig(newConfig *Config) {
	m.configMu.Lock()
	defer m.configMu.Unlock()

	m.config = newConfig

	// Recreate notification manager with new config
	newNotifier := NewNotificationManager(newConfig.Notifications)
	if newNotifier != nil {
		m.logger.Printf("Config reloaded: Notification manager updated with %d provider(s)", len(newNotifier.notifiers))
	}
	m.notifier = newNotifier

	m.logger.Printf("Config reloaded: Watching for abnormal activity: %v", newConfig.AnomalousPatterns)
}

// Start begins monitoring connections
func (m *ConnectionMonitor) Start(stop <-chan struct{}) {
	m.configMu.RLock()
	interval := m.config.Interval
	m.configMu.RUnlock()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			m.checkConnections()
		}
	}
}

// checkConnections retrieves and analyzes current connections
func (m *ConnectionMonitor) checkConnections() {
	connections, err := m.getConnections()
	if err != nil {
		m.logger.Printf("Error getting connections: %v", err)
		return
	}

	// Deduplicate LISTEN connections: track seen local ports to avoid reporting IPv4 and IPv6 separately
	seenListenPorts := make(map[int]bool)

	// Check for new or changed connections
	currentKeys := make(map[string]bool)
	for _, conn := range connections {
		// Skip duplicate LISTEN on same port for IPv4/IPv6
		// Report only the first one seen (typically IPv4)
		if isSocketListening(conn) && conn.LocalPort > 0 {
			if seenListenPorts[conn.LocalPort] {
				// Already reported this LISTEN port, skip the duplicate (IPv6 variant)
				continue
			}
			seenListenPorts[conn.LocalPort] = true
		}

		key := conn.connectionKey()
		currentKeys[key] = true

		m.configMu.RLock()
		alertsOnly := m.config.AlertsOnly
		verbose := m.config.Verbose
		m.configMu.RUnlock()

		if _, existed := m.prevConns[key]; !existed && !alertsOnly {
			// New connection
			if verbose {
				m.logger.Printf("NEW: %s", conn.String())
			}
		}

		// Check for anomalies
		if conn.IsAnomalous {
			m.alertOnAnomaly(conn)
		}
	}

	// Check for closed connections
	m.configMu.RLock()
	alertsOnly := m.config.AlertsOnly
	verbose := m.config.Verbose
	m.configMu.RUnlock()

	for key, prevConn := range m.prevConns {
		if !currentKeys[key] && !alertsOnly {
			if verbose {
				m.logger.Printf("CLOSED: %s", prevConn.String())
			}
		}
	}

	m.prevConns = make(map[string]*Connection)
	for _, conn := range connections {
		m.prevConns[conn.connectionKey()] = conn
	}
}

// getConnections retrieves all network connections with process information
func (m *ConnectionMonitor) getConnections() ([]*Connection, error) {
	var result []*Connection

	// Try to get connections per process first, as it provides accurate PID information
	// This is more reliable than net.Connections() which often returns PID 0
	procs, err := process.Processes()
	if err == nil {
		result = m.getConnectionsFromProcesses(procs)
		if len(result) > 0 {
			return result, nil
		}
	}

	// Fallback to net.Connections if per-process method fails
	// Try both IPv4 and IPv6 for better coverage
	conns, err := net.Connections("inet")
	if err != nil {
		return m.getConnectionsPerProcess()
	}

	// Also get IPv6 connections for full protocol support
	conns6, err := net.Connections("inet6")
	if err != nil {
		// Final fallback: try per-process again
		return m.getConnectionsPerProcess()
	}

	for _, conn := range conns {
		// Filter by PID if specified
		m.configMu.RLock()
		pid := m.config.PID
		m.configMu.RUnlock()

		if pid != 0 && int(conn.Pid) != pid {
			continue
		}

		procName := m.getProcessName(uint32(conn.Pid))
		if procName == "" {
			procName = "unknown"
		}

		// Track all TCP states and UDP datagrams
		// For UDP, status may be empty or "NONE" since it's connectionless
		state := conn.Status
		if state == "" {
			state = "NONE"
		}

		c := &Connection{
			PID:         uint32(conn.Pid),
			ProcessName: procName,
			LocalIP:     ParseIP(conn.Laddr.IP),
			LocalPort:   int(conn.Laddr.Port),
			RemoteIP:    ParseIP(conn.Raddr.IP),
			RemotePort:  int(conn.Raddr.Port),
			Protocol:    getProtocolString(conn.Type),
			State:       state,
		}

		m.analyzeConnection(c)
		result = append(result, c)
	}

	// Process IPv6 connections
	for _, conn := range conns6 {
		// Filter by PID if specified
		m.configMu.RLock()
		pid := m.config.PID
		m.configMu.RUnlock()

		if pid != 0 && int(conn.Pid) != pid {
			continue
		}

		procName := m.getProcessName(uint32(conn.Pid))
		if procName == "" {
			procName = "unknown"
		}

		// Track all TCP states and UDP datagrams
		state := conn.Status
		if state == "" {
			state = "NONE"
		}

		c := &Connection{
			PID:         uint32(conn.Pid),
			ProcessName: procName,
			LocalIP:     ParseIP(conn.Laddr.IP),
			LocalPort:   int(conn.Laddr.Port),
			RemoteIP:    ParseIP(conn.Raddr.IP),
			RemotePort:  int(conn.Raddr.Port),
			Protocol:    getProtocolString(conn.Type),
			State:       state,
		}

		m.analyzeConnection(c)
		result = append(result, c)
	}

	return result, nil
}

// getConnectionsFromProcesses gets connections by iterating through all processes
func (m *ConnectionMonitor) getConnectionsFromProcesses(procs []*process.Process) []*Connection {
	var result []*Connection

	for _, p := range procs {
		m.configMu.RLock()
		pid := m.config.PID
		m.configMu.RUnlock()

		if pid != 0 && int(p.Pid) != pid {
			continue
		}

		conns, err := p.Connections()
		if err != nil {
			// Permission denied or process terminated, skip
			continue
		}

		procName, _ := p.Name()

		for _, conn := range conns {
			// Track all TCP states and UDP datagrams
			// For UDP, status may be empty or "NONE" since it's connectionless
			state := conn.Status
			if state == "" {
				state = "NONE"
			}

			c := &Connection{
				PID:         uint32(p.Pid),
				ProcessName: procName,
				LocalIP:     ParseIP(conn.Laddr.IP),
				LocalPort:   int(conn.Laddr.Port),
				RemoteIP:    ParseIP(conn.Raddr.IP),
				RemotePort:  int(conn.Raddr.Port),
				Protocol:    getProtocolString(conn.Type),
				State:       state,
			}

			m.analyzeConnection(c)
			result = append(result, c)
		}
	}

	return result
}

// getConnectionsPerProcess gets connections from each process individually
func (m *ConnectionMonitor) getConnectionsPerProcess() ([]*Connection, error) {
	procs, err := process.Processes()
	if err != nil {
		return []*Connection{}, err
	}

	result := m.getConnectionsFromProcesses(procs)
	return result, nil
}

// analyzeConnection checks if a connection is anomalous
func (m *ConnectionMonitor) analyzeConnection(c *Connection) {
	m.configMu.RLock()
	defer m.configMu.RUnlock()

	reasons := []string{}
	remoteIPExcluded := m.config.IsRemoteIPExcluded(c.RemoteIP)

	// Check for suspicious TCP states (connection initiation attempts)
	if !remoteIPExcluded && c.Protocol == "tcp" && c.State == "SYN_SENT" && c.RemotePort != 80 && c.RemotePort != 443 {
		serviceName := GetServiceName(c.RemotePort)
		if serviceName != "" {
			reasons = append(reasons, fmt.Sprintf("TCP_SYN_SENT_%s[%s](%d)", c.RemoteIP, serviceName, c.RemotePort))
		} else {
			reasons = append(reasons, fmt.Sprintf("TCP_SYN_SENT_%s:%d", c.RemoteIP, c.RemotePort))
		}
	}

	// Check for listening ports (potential backdoors)
	// Track LISTEN alerts by local port and only alert when the port is not whitelisted.
	var standardPorts map[int]bool
	switch c.Protocol {
	case "tcp":
		standardPorts = m.config.StandardPortsTCP
	case "udp":
		standardPorts = m.config.StandardPortsUDP
	}

	// Check if socket is listening (works for both TCP LISTEN and UDP bound sockets)
	isListening := isSocketListening(c)

	// For UDP, only detect listening ports if UDP pattern is enabled
	// For TCP, always detect listening ports
	shouldDetectListen := c.Protocol != "udp" || m.config.AnomalousPatterns["udp"]

	if isListening && c.LocalPort > 0 && !standardPorts[c.LocalPort] && !m.config.IsProcessPortExcluded(c.ProcessName, c.LocalPort) && shouldDetectListen {
		serviceName := GetServiceName(c.LocalPort)
		if serviceName != "" {
			reasons = append(reasons, fmt.Sprintf("LISTEN_%s(%d)", serviceName, c.LocalPort))
		} else {
			reasons = append(reasons, fmt.Sprintf("LISTEN_PORT_%d", c.LocalPort))
		}
	}

	// Check for UDP traffic (often used by malware for C2, DNS tunneling, etc.)
	if !remoteIPExcluded && m.config.AnomalousPatterns["udp"] && c.Protocol == "udp" && c.RemotePort > 0 && !m.config.StandardPortsUDP[c.RemotePort] {
		// Flag non-standard UDP traffic
		reasons = append(reasons, fmt.Sprintf("UDP_TRAFFIC_%s:%d", c.RemoteIP, c.RemotePort))
	}

	// Check for SSH connections
	if !remoteIPExcluded && m.config.AnomalousPatterns["ssh"] && c.RemotePort == 22 {
		reasons = append(reasons, "SSH_OUTBOUND")
	}

	// Check for Telnet
	if !remoteIPExcluded && m.config.AnomalousPatterns["telnet"] && c.RemotePort == 23 {
		reasons = append(reasons, "TELNET_OUTBOUND")
	}

	// Check for common RDP/VNC ports
	if !remoteIPExcluded && m.config.AnomalousPatterns["ssh"] && (c.RemotePort == 3389 || c.RemotePort == 5900) {
		serviceName := GetServiceName(c.RemotePort)
		if serviceName != "" {
			reasons = append(reasons, fmt.Sprintf("REMOTE_ACCESS_%s(%d)", serviceName, c.RemotePort))
		} else {
			reasons = append(reasons, fmt.Sprintf("REMOTE_ACCESS_PORT_%d", c.RemotePort))
		}
	}

	// Check for private IP connections if enabled
	if !remoteIPExcluded && m.config.AnomalousPatterns["private_ip"] && IsPrivateIP(c.RemoteIP) {
		reasons = append(reasons, "PRIVATE_IP_CONN")
	}

	// Check for external connections if enabled
	if !remoteIPExcluded && m.config.AnomalousPatterns["external"] && IsPublicIP(c.RemoteIP) {
		reasons = append(reasons, "EXTERNAL_CONN")
	}

	// Check for high ports if enabled (ephemeral range)
	if !remoteIPExcluded && m.config.AnomalousPatterns["high_ports"] && c.RemotePort > 49152 && !m.config.IsProcessPortExcluded(c.ProcessName, c.RemotePort) {
		serviceName := GetServiceName(c.RemotePort)
		if serviceName != "" {
			reasons = append(reasons, fmt.Sprintf("HIGH_PORT_%s(%d)", serviceName, c.RemotePort))
		} else {
			reasons = append(reasons, fmt.Sprintf("HIGH_PORT_%d", c.RemotePort))
		}
	}

	// Check for low/privileged ports if enabled
	if !remoteIPExcluded && m.config.AnomalousPatterns["low_ports"] && c.RemotePort > 0 && c.RemotePort < 1024 && c.RemotePort != 80 && c.RemotePort != 443 {
		serviceName := GetServiceName(c.RemotePort)
		if serviceName != "" {
			reasons = append(reasons, fmt.Sprintf("LOW_PORT_%s(%d)", serviceName, c.RemotePort))
		} else {
			reasons = append(reasons, fmt.Sprintf("LOW_PORT_%d", c.RemotePort))
		}
	}

	// Check for non-standard ports (if not in standard list)
	standardPorts = m.config.StandardPortsTCP
	if c.Protocol == "udp" {
		standardPorts = m.config.StandardPortsUDP
	}
	if !standardPorts[c.RemotePort] && c.RemotePort > 1024 && !m.config.AnomalousPatterns["high_ports"] {
		// Only flag unusual ports that aren't in our standard list
		if c.RemotePort > 5000 && c.RemotePort < 49152 {
			// Might be a custom service
			// reasons = append(reasons, fmt.Sprintf("NON_STANDARD_PORT_%d", c.RemotePort))
		}
	}

	if len(reasons) > 0 {
		c.IsAnomalous = true
		c.AnomalousReasons = reasons
	}
}

// isSocketListening checks if a socket is listening for both TCP and UDP protocols.
// For TCP, a listening socket has State == "LISTEN".
// For UDP, a listening socket is bound locally with no remote endpoint:
// State is "NONE" or empty, LocalPort > 0, RemotePort == 0,
// and RemoteIP is empty, "0.0.0.0", or "::"
func isSocketListening(c *Connection) bool {
	if c.State == "LISTEN" {
		return true
	}
	if c.Protocol == "udp" && (c.State == "NONE" || c.State == "") && c.LocalPort > 0 && c.RemotePort == 0 && (c.RemoteIP == "" || c.RemoteIP == "0.0.0.0" || c.RemoteIP == "::") {
		return true
	}
	return false
}

// alertOnAnomaly logs an alert for anomalous activity
func (m *ConnectionMonitor) alertOnAnomaly(c *Connection) {
	key := c.connectionKey()
	lastAlert, seen := m.alertHistory[key]

	m.configMu.RLock()
	alertCooldown := 1 * time.Minute
	if isSocketListening(c) && m.config != nil && m.config.ListenAlertCooldown > 0 {
		alertCooldown = m.config.ListenAlertCooldown
	}
	notifier := m.notifier
	notificationConfig := m.config.Notifications
	m.configMu.RUnlock()

	if seen && time.Since(lastAlert) < alertCooldown {
		return
	}

	m.logger.Printf("⚠️  ALERT: %s", c.DetailedString())
	m.alertHistory[key] = time.Now()

	// Send notification only once per cooldown key to avoid spam.
	// LISTEN sockets bound to 0.0.0.0/:: are keyed by local port, not remote address.
	if notifier != nil {
		if c.bypassNotificationCooldown() {
			listenCooldown := time.Duration(0)
			if notificationConfig != nil {
				listenCooldown = notificationConfig.ListenNotificationCooldown
			}

			if listenCooldown <= 0 {
				if err := notifier.SendAlert(c); err != nil {
					m.logger.Printf("Failed to send notification: %v", err)
				}
				return
			}

			notificationKey := c.notificationCooldownKey()
			lastNotification, notified := m.notificationHistory[notificationKey]
			if !notified || time.Since(lastNotification) > listenCooldown {
				if err := notifier.SendAlert(c); err != nil {
					m.logger.Printf("Failed to send notification: %v", err)
				} else {
					m.notificationHistory[notificationKey] = time.Now()
				}
			}
			return
		}

		notificationKey := c.notificationCooldownKey()
		lastNotification, notified := m.notificationHistory[notificationKey]

		// Get notification cooldown period from config (default 24h)
		cooldown := 24 * time.Hour
		if notificationConfig != nil && notificationConfig.NotificationCooldown > 0 {
			cooldown = notificationConfig.NotificationCooldown
		}

		// Send notification only if never sent before, or cooldown period has elapsed
		if !notified || time.Since(lastNotification) > cooldown {
			if err := notifier.SendAlert(c); err != nil {
				m.logger.Printf("Failed to send notification: %v", err)
			} else {
				m.notificationHistory[notificationKey] = time.Now()
			}
		}
	}
}

// getProtocolString converts socket type to protocol string
func getProtocolString(sockType uint32) string {
	switch sockType {
	case 1:
		return "tcp"
	case 2:
		return "udp"
	default:
		return fmt.Sprintf("proto_%d", sockType)
	}
}

// getProcessName gets the name of a process by PID
func (m *ConnectionMonitor) getProcessName(pid uint32) string {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return ""
	}

	name, err := p.Name()
	if err != nil {
		return ""
	}

	return name
}

// connectionKey creates a unique key for a connection
func (c *Connection) connectionKey() string {
	return fmt.Sprintf("%d_%s_%d_%s_%d", c.PID, c.RemoteIP, c.RemotePort, c.LocalIP, c.LocalPort)
}
