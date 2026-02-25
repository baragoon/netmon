# NetMon - Network Connections Monitor

A simple Linux network connections monitor written in Go to detect abnormal network activity.

## Features

- **Monitor Network Connections**: Track all established network connections on the system
- **Detect Anomalies**: Alert on suspicious patterns like:
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

- Go 1.21 or higher
- Linux system (tested on Ubuntu, Debian, CentOS)
- Root privileges (for full network visibility)

## Installation

```bash
# Clone the repository
git clone <repo-url>
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
sudo ./netmon -interval 10s

# Only show alerts (filter normal activity)
sudo ./netmon -alerts-only

# Enable verbose output
sudo ./netmon -verbose

# Log to file (outputs to both stdout and file)
sudo ./netmon -log /var/log/netmon.log

# Monitor specific process (by PID)
sudo ./netmon -interval 5s  # Add filtering by PID if needed
```

### Docker Usage

```bash
# Using Docker Compose (easiest)
docker-compose up -d
docker-compose logs -f

# Or build and run manually
docker build -t netmon .
docker run --rm --network host netmon -interval 5s -alerts-only
```

NetMon uses `--network host` mode to monitor the host's network connections from inside the container.

### Command-line Options

- `-interval`: Monitoring interval (default: 5s)
- `-verbose`: Show all connections, not just anomalies
- `-alerts-only`: Only show flagged suspicious connections
- `-config`: Path to JSON configuration file
- `-log`: Optional path to log file (logs to stdout if not specified)

### Configuration File

Create a JSON config file to customize detection rules:

```json
{
  "interval": "5s",
  "standard_ports": [80, 443, 53],
  "anomalous_patterns": ["ssh", "telnet"],
  "watch_processes": [],
  "verbose": false,
  "alerts_only": true,
  "pid": 0
}
```

Then run with:
```bash
sudo ./netmon -config /path/to/config.json
```

## Anomalous Patterns

Each pattern controls what types of connections trigger alerts. Enable patterns by including them in the `anomalous_patterns` array:

### Available Patterns

| Pattern | Description | Default |
|---------|-------------|---------|
| `ssh` | Outgoing SSH connections (port 22) | **enabled** |
| `telnet` | Telnet connections (port 23) | **enabled** |
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

**Custom strict monitoring (all patterns enabled):**
```json
{
  "anomalous_patterns": ["ssh", "telnet", "private_ip", "external", "high_ports", "low_ports"]
}
```

## Standard Ports

By default, only these ports are considered "normal":
- **80** - HTTP
- **443** - HTTPS  
- **53** - DNS

Connections to other ports can be flagged if supported by your anomalous_patterns config. You can customize the standard ports list in your config file:

```json
{
  "standard_ports": [80, 443, 53, 3306, 5432, 6379],
  "anomalous_patterns": ["ssh", "telnet"]
}
```

This expands the "safe" ports to include MySQL (3306), PostgreSQL (5432), and Redis (6379).

## Notifications

NetMon supports sending alerts to multiple notification services. Configure notifications in your config.json to get real-time alerts via your preferred channels.

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
| `{ip}` | Remote IP address | 203.0.113.42 |
| `{port}` | Remote port number | 22 |
| `{service}` | Process/service name | ssh, curl |
| `{protocol}` | Connection protocol | tcp, udp |
| `{local_ip}` | Local IP address | 192.168.1.100 |
| `{local_port}` | Local port number | 54321 |
| `{pid}` | Process ID | 1234 |
| `{reason}` | Alert reason | SSH_OUTBOUND, TELNET_OUTBOUND |
| `{timestamp}` | Alert timestamp | 2026-02-25T20:55:00Z |

### Pushover Setup

1. Create account at https://pushover.net
2. Create application and get API key
3. Get your user key
4. Configure in config.json:

```json
{
  "notifications": {
    "enabled": true,
    "title_template": "🚨 {service} Connection Alert",
    "message_template": "{service} connected to {ip}:{port}\nReason: {reason}",
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
    "title_template": "🚨 Network Alert: {service}",
    "message_template": "{service} -> {ip}:{port} ({reason})",
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

1. Get API key from https://www.pushbullet.com/account/settings
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
[netmon] 2026/02/25 10:30:50 monitor.go:145: ⚠️  ALERT: ssh (5678) -> 192.168.1.100:22 [tcp ESTABLISHED] [ALERT: SSH_OUTBOUND]
```

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
- Be cautious with -verbose flag on high-traffic systems
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
sudo ./netmon -interval 30s
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
