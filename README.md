# NetMon - Network Connections Monitor

A simple Linux network connections monitor written in Go to detect abnormal network activity.

## Features

- **Monitor Network Connections**: Track all TCP states and active UDP datagrams on the system
- **Track All TCP States**: Monitor connections in all states (SYN_SENT, ESTABLISHED, LISTEN, etc.) to catch malware during connection initiation
- **UDP Monitoring**: Track UDP datagrams which are often used for DNS tunneling and C2 communications
- **Detect Anomalies**: Alert on suspicious patterns like:
  - TCP connection attempts (SYN_SENT) to non-standard ports
  - Listening ports on non-privileged ports (potential backdoors)
  - UDP traffic to non-DNS ports
  - Outgoing SSH connections (port 22)
  - Telnet connections (port 23)  
  - Remote access ports (RDP 3389, VNC 5900)
  - Private IP connections
  - External connections
  - Non-standard ports
  - Privileged ports
- **Per-Process Monitoring**: See which processes are making connections
- **Configurable Rules**: Define which patterns to monitor
- **Low Resource Usage**: Runs as a background service
- **Verbose Logging**: Optional detailed output

## Requirements

- Go 1.24 or higher
- Linux system (tested on Ubuntu, Debian, CentOS)
- Root privileges (for full network visibility)

## Installation

```bash
# Clone the repository
git clone https://github.com/baragoon/netmon.git
cd netmon

# Build the project
go build -o netmon .

# Or install directly
go install .
```

## Usage

### Basic Usage

```bash
# Run with default settings (5 second intervals)
sudo ./netmon

# Run with custom interval
sudo ./netmon --interval 10s

# Only show alerts (filter normal activity)
sudo ./netmon --alerts-only

# Enable verbose output
sudo ./netmon --verbose

# Log to file (outputs to both stdout and file)
sudo ./netmon --log /var/log/netmon.log

# Monitor specific process (by PID)
sudo ./netmon --interval 5s  # Add filtering by PID if needed
```

### Docker Usage

```bash
# Using Docker Compose (easiest)
docker-compose up -d
docker-compose logs -f

# Or build and run manually
docker build -t netmon .
docker run --rm --network host netmon --interval 5s --alerts-only
```

NetMon uses `--network host` mode to monitor the host's network connections from inside the container.

**Editing Config in Docker:** When using Docker Compose, the config file is mounted from `./config.json` on the host. You can edit this file directly on your host machine, and NetMon will automatically reload it inside the container. Changes take effect immediately without restarting the container.

### Self-hosted GitHub Actions Runner (Docker)

If you run the Docker workflow on a `self-hosted` GitHub Actions runner, Docker must already be available to the runner user.

- Linux runner:
  - Ensure the Docker daemon is running.
  - Ensure the runner user is in the `docker` group.
  - Example host setup: `sudo usermod -aG docker <runner-user>` and then restart the runner session/service.
- macOS runner:
  - Ensure Docker Desktop is running.
  - Ensure the runner process is started under the same account that can access Docker Desktop.

The workflow does not attempt to change `/var/run/docker.sock` permissions at runtime.

### Command-line Options

- `--interval`: Monitoring interval (default: 5s)
- `--verbose`: Show all connections, not just anomalies
- `--alerts-only`: Only show flagged suspicious connections
- `--config`: Path to JSON configuration file
- `--log`: Optional path to log file (logs to stdout if not specified)

### Configuration File

**Auto-loading:** If you place a `config.json` file in the same directory as the `netmon` binary, it will be automatically loaded without needing the `--config` flag.

Create a JSON config file to customize detection rules:

```json
{
  "interval": "5s",
  "listen_alert_cooldown": "1m",
  "standard_ports_tcp": [80, 443, 53],
  "standard_ports_udp": [53, 123, 67, 68],
  "anomalous_patterns": ["ssh", "telnet"],
  "process_port_exclusions": {
    "chromium": ["49152-65535"],
    "forgejo-runner": ["32768-65535"]
  },
  "allowed_remote_ips": ["192.0.2.1", "203.0.113.0/24"],
  "watch_processes": [],
  "verbose": false,
  "alerts_only": true,
  "pid": 0
}
```

`listen_alert_cooldown` controls log alert rate-limiting for LISTEN events (default: `1m`).

`process_port_exclusions` lets you suppress alerts for specific remote ports per process (exact ports like `"443"` or ranges like `"49152-65535"`). This is useful for noisy client apps that use ephemeral ports.

`allowed_remote_ips` suppresses high-port alerts for specific remote IPs/CIDRs. NetMon also suppresses high-port alerts for loopback/private/link-local addresses by default (IPv4 + IPv6).

**Live Config Reload:** NetMon automatically watches the config file for changes and reloads it without requiring a restart. When you edit and save `config.json`, the new settings take effect immediately. This works both when running the binary directly and in Docker containers.

Then run with:

```bash
sudo ./netmon --config /path/to/config.json
```

## Anomalous Patterns

Each pattern controls what types of connections trigger alerts. Enable patterns by including them in the `anomalous_patterns` array:

### Available Patterns

| Pattern | Description | Default |
|---------|-------------|---------|
| `ssh` | Outgoing SSH connections (port 22) | **enabled** |
| `telnet` | Telnet connections (port 23) | **enabled** |
| `udp` | Non-standard UDP traffic (excludes standard UDP ports) | disabled |
| `private_ip` | Connections to private IP ranges (10.x, 192.168.x, 172.16-31.x) | disabled |
| `external` | All external (public IP) connections | disabled |
| `high_ports` | Ephemeral port range (49152+) | disabled |
| `low_ports` | Privileged ports below 1024 (except 80/443) | disabled |

### Configuration Examples

**Alert only on SSH and Telnet (default):**

```json
{
  "anomalous_patterns": ["ssh", "telnet"]
}
```

**Alert on all remote access attempts:**

```json
{
  "anomalous_patterns": ["ssh", "telnet", "private_ip"]
}
```

**Monitor for suspicious data exfiltration (external + high ports):**

```json
{
  "anomalous_patterns": ["external", "high_ports"]
}
```

**Reduce high-port noise for specific apps (balanced):**

```json
{
  "anomalous_patterns": ["ssh", "telnet", "high_ports"],
  "process_port_exclusions": {
    "chromium": ["49152-65535"],
    "chrome": ["49152-65535"],
    "forgejo-runner": ["32768-65535"]
  },
  "allowed_remote_ips": ["192.0.2.1", "203.0.113.0/24"]
}
```

Note: LISTEN alerts on non-standard ports are still reported, including high ports.

**Custom strict monitoring (all patterns enabled):**

```json
{
  "anomalous_patterns": ["ssh", "telnet", "private_ip", "external", "high_ports", "low_ports"]
}
```

## Standard Ports

NetMon uses separate standard port lists for TCP and UDP protocols:

**Default TCP Ports (standard_ports_tcp):**

- **80** - HTTP
- **443** - HTTPS  
- **53** - DNS

**Default UDP Ports (standard_ports_udp):**

- **53** - DNS
- **123** - NTP (Network Time Protocol)
- **67/68** - DHCP (Dynamic Host Configuration Protocol)

You can customize both lists in your config file:

```json
{
  "standard_ports_tcp": [80, 443, 53, 3306, 5432],
  "standard_ports_udp": [53, 123, 67, 68, 51820],
  "anomalous_patterns": ["ssh", "telnet", "udp"]
}
```

This example:

- Adds MySQL (3306) and PostgreSQL (5432) to standard TCP ports
- Adds WireGuard (51820) to standard UDP ports to prevent VPN alerts

## Notifications

NetMon supports sending alerts to multiple notification services. Configure notifications in your config.json to get real-time alerts via your preferred channels.

### Notification Deduplication

To avoid spam, **notifications are sent only once per remote address** (IP:Port combination) within a configurable cooldown period. When the same address is detected multiple times:

- **Logs**: Show all occurrences (rate-limited to once per minute per full connection)
- **Notifications**: Sent only once per cooldown period per remote address

Default cooldown is **24 hours**, but you can customize it:

```json
{
  "notifications": {
    "enabled": true,
    "notification_cooldown": "2h",
    "listen_notification_cooldown": "30s",
    "pushover": {
      "enabled": true,
      "api_key": "your_key",
      "user_key": "your_user_key"
    }
  }
}
```

**Cooldown Examples:**

- `"1h"` - Notify once per hour per address
- `"2h"` - Notify once every 2 hours
- `"24h"` - Notify once per day (default)
- `"168h"` - Notify once per week
- `"30m"` - Notify once every 30 minutes

**LISTEN Notification Cooldown:**

- `listen_notification_cooldown` applies only to LISTEN alerts on `0.0.0.0` / `::`.
- Default is `"0s"` (disabled), meaning those LISTEN notifications are sent immediately.
- Set a value like `"30s"` or `"2m"` to deduplicate per LISTEN port during that window.

**Example Behavior** (with `notification_cooldown: "2h"`):

If malware at `203.0.113.42:8080` is detected:

- First detection (00:00): Alert logged + notification sent ✉️
- Subsequent detections (00:05, 00:30): Alerts logged only, no notification
- Detection at 02:01 (>2h later): Alert logged + notification sent again ✉️

This prevents notification flooding while maintaining comprehensive logs for forensic analysis.

### Supported Notification Providers

1. **Pushover** - Push notifications to iOS/Android/Desktop
2. **ntfy.sh** - Simple HTTP-based push notifications
3. **Pushbullet** - Cross-device notifications
4. **Telegram** - Bot-based alerts to Telegram chats
5. **Webhook** - Generic HTTP webhooks for custom integrations

### Notification Variables

Use dynamic variables in alert titles and messages to customize notifications:

| Variable | Description | Example |
|----------|-------------|---------|
| `{hostname}` | Server hostname | server-1, web-prod-01 |
| `{ip}` | Remote IP address | 203.0.113.42 |
| `{port}` | Remote port number | 22 |
| `{service}` | Process/service name | ssh, curl |
| `{protocol}` | Connection protocol | tcp, udp |
| `{local_ip}` | Local IP address | 198.51.100.100 |
| `{local_port}` | Local port number | 54321 |
| `{pid}` | Process ID | 1234 |
| `{reason}` | Alert reason | SSH_OUTBOUND, TELNET_OUTBOUND |
| `{timestamp}` | Alert timestamp | 2026-02-25T20:55:00Z |

### Pushover Setup

1. Create account at <https://pushover.net>
2. Create application and get API key
3. Get your user key
4. Configure in config.json:

```json
{
  "notifications": {
    "enabled": true,
    "title_template": "🚨 [{hostname}] {service} Connection Alert",
    "message_template": "Host: {hostname}\n{service} connected to {ip}:{port}\nReason: {reason}",
    "pushover": {
      "enabled": true,
      "api_key": "your_pushover_api_key",
      "user_key": "your_pushover_user_key",
      "device": "iphone",
      "sound": "incoming"
    }
  }
}
```

### ntfy.sh Setup

Simple setup with no authentication required:

```json
{
  "notifications": {
    "enabled": true,
    "title_template": "🚨 [{hostname}] Network Alert: {service}",
    "message_template": "Host: {hostname}\n{service} -> {ip}:{port} ({reason})",
    "ntfy": {
      "enabled": true,
      "topic": "my-netmon-alerts",
      "base_url": "https://ntfy.sh"
    }
  }
}
```

Then subscribe to alerts at: `https://ntfy.sh/my-netmon-alerts`

### Pushbullet Setup

1. Get API key from <https://www.pushbullet.com/account/settings>
2. Configure:

```json
{
  "notifications": {
    "enabled": true,
    "pushbullet": {
      "enabled": true,
      "api_key": "your_pushbullet_api_key"
    }
  }
}
```

### Telegram Setup

1. Create bot with [@BotFather](https://t.me/botfather) on Telegram
2. Get bot token
3. Get your chat ID (send message to your bot, check updates)
4. Configure:

```json
{
  "notifications": {
    "enabled": true,
    "title_template": "🚨 NetMon Alert",
    "message_template": "*{service}*\n\n{ip}:{port} via {protocol}\n\n_Reason: {reason}_",
    "telegram": {
      "enabled": true,
      "bot_token": "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
      "chat_id": "987654321"
    }
  }
}
```

Telegram supports Markdown formatting.

### Webhook Setup

Send alerts to any HTTP endpoint:

```json
{
  "notifications": {
    "enabled": true,
    "webhook": {
      "enabled": true,
      "url": "https://your-server.com/api/alerts",
      "method": "POST",
      "headers": {
        "Authorization": "Bearer your_token",
        "Content-Type": "application/json"
      }
    }
  }
}
```

Webhook receives JSON payload:

```json
{
  "title": "🚨 Suspicious Network Activity",
  "message": "ssh connected to 203.0.113.42:22",
  "timestamp": "2026-02-25T20:55:00Z"
}
```

### Complete Example with Multiple Providers

```json
{
  "interval": "5s",
  "anomalous_patterns": ["ssh", "telnet"],
  "notifications": {
    "enabled": true,
    "title_template": "🚨 Alert: {service}",
    "message_template": "{service} ({pid}) -> {ip}:{port}\nReason: {reason}\nTime: {timestamp}",
    "telegram": {
      "enabled": true,
      "bot_token": "YOUR_TOKEN",
      "chat_id": "YOUR_CHAT_ID"
    },
    "ntfy": {
      "enabled": true,
      "topic": "netmon"
    },
    "webhook": {
      "enabled": true,
      "url": "https://api.example.com/security-events"
    }
  }
}
```

All enabled providers will receive alerts simultaneously.

## Example Output

```
[netmon] 2026/02/25 10:30:45 monitor.go:35: Starting network connections monitor (interval: 5s)
[netmon] 2026/02/25 10:30:45 monitor.go:36: Watching for abnormal activity: map[ssh:true telnet:true]
[netmon] 2026/02/25 10:30:50 monitor.go:91: NEW: curl (1234) -> 203.0.113.42:443 [tcp ESTABLISHED]
[netmon] 2026/02/25 10:30:50 monitor.go:145: ⚠️  ALERT: ssh (5678) -> 198.51.100.100:22 [tcp ESTABLISHED] [ALERT: SSH_OUTBOUND]
```

## Connection State Monitoring

NetMon monitors **all TCP connection states** and **UDP datagrams**, not just established connections. This comprehensive approach helps detect malicious activity at different stages:

### TCP States Tracked

- **SYN_SENT**: Connection initiation attempts - catches malware as it tries to connect
- **SYN_RECV**: Incoming connection requests - detects port scanning
- **ESTABLISHED**: Active connections - normal traffic monitoring  
- **LISTEN**: Open listening ports - detects backdoors and trojans
- **CLOSE_WAIT, FIN_WAIT1/2**: Connection closing - tracks cleanup
- **TIME_WAIT**: Recently closed connections

### Why Track All States?

Monitoring only ESTABLISHED connections misses critical security events:

- **Malware starting sessions**: SYN_SENT states reveal connection attempts before they succeed
- **Backdoor services**: LISTEN states expose unauthorized services waiting for commands
- **Port scanning**: SYN_RECV patterns indicate reconnaissance activity

### UDP Monitoring

UDP is connectionless, so it doesn't have states like TCP. NetMon tracks all active UDP datagrams because:

- **DNS tunneling**: Malware often uses DNS (port 53) to bypass firewalls
- **C2 communications**: Command & control servers frequently use UDP
- **Data exfiltration**: UDP's stateless nature makes it popular for covert channels
- **VPN/Tunneling**: WireGuard and other VPN protocols use UDP

Alerts trigger for UDP traffic to non-standard ports when the `udp` anomalous pattern is enabled. Standard UDP ports (DNS, NTP, DHCP by default) are excluded from alerts. You can customize which UDP ports are considered standard using the `standard_ports_udp` config option.

## How It Works

1. **Connection Detection**: Uses gopsutil to enumerate network connections
2. **Process Identification**: Maps connections to their originating process
3. **Anomaly Analysis**: Checks each connection against configured rules
4. **Alerting**: Logs anomalies with rate limiting (1 per minute per connection)
5. **Tracking**: Maintains history to detect new/closed connections

## Limitations

- Requires root/sudo to see all connections
- Some system calls may not work on all Linux distributions
- High-frequency monitoring may consume more CPU
- Does not decrypt encrypted traffic

## Performance

- Memory usage: ~10-50 MB (depending on connection count)
- CPU usage: <1% with 5-second intervals
- Scales to thousands of connections

## Security Considerations

- Run with minimum required privileges
- Be cautious with --verbose flag on high-traffic systems
- SSH/Telnet alerts are defaults - customize as needed
- Consider running in a container or VM for isolation

## Troubleshooting

### "Permission denied" errors

This tool requires root privileges:

```bash
sudo ./netmon
```

### Missing connections on some systems

Some Linux distributions require additional capabilities:

```bash
sudo setcap cap_net_admin,cap_sys_chroot,cap_dac_override=ep ./netmon
```

### High resource usage

Increase the monitoring interval:

```bash
sudo ./netmon --interval 30s
```

## Development

```bash
# Download dependencies
go mod download

# Run tests (if added)
go test ./...

# Build for distribution
GOOS=linux GOARCH=amd64 go build -o netmon .
```

## License

MIT License

## Contributing

Pull requests welcome. Please ensure code follows Go conventions and includes tests.

## Author

Built for network security monitoring and system administration.
