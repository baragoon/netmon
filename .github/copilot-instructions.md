# NetMon Project Instructions

This is a network connections monitor written in Go.

## Project Overview

NetMon monitors Linux network connections in real-time and alerts on suspicious activity patterns such as:
- Outgoing SSH connections
- Telnet connections
- Remote access ports
- Non-standard ports
- External connections
- Private IP connections (optional)

## Project Structure

- `main.go` - Entry point with CLI flags
- `monitor/config.go` - Configuration loading and defaults
- `monitor/connection.go` - Connection data structure and utilities
- `monitor/monitor.go` - Core monitoring logic
- `go.mod` - Go module file with dependencies
- `README.md` - Full documentation

## Dependencies

- `github.com/shirou/gopsutil/v3` - For system network information

## Building

```bash
go build -o netmon .
```

## Running

```bash
sudo ./netmon
sudo ./netmon -interval 10s -verbose
sudo ./netmon -alerts-only -config ./config.json
```

## Key Features

- Real-time connection monitoring
- Configurable anomaly detection rules
- Per-process connection tracking
- JSON configuration support
- Low resource overhead
- Rate-limited alerting

## Testing

Run with verbose mode to see all connections:
```bash
sudo ./netmon -verbose
```

Test SSH detection:
```bash
ssh user@example.com &
sudo ./netmon -interval 2s -alerts-only
```
