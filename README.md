# Go Agent

This directory contains the Go server monitoring agent and produces a single self-contained binary that runs on Linux (amd64/arm64/armv7), macOS (amd64/arm64), and Windows (amd64).

## Features

- Socket.IO control-plane connection with HMAC (`clientId`, `ts`, `sig`) auth.
- Periodic telemetry (`cpu`, `mem`, `load`, `uptime`) via gopsutil.
- Remote shell with PTY (`creack/pty` on Unix, pipe fallback on Windows).
- `admin_run` command executor with allow-list and per-command timeouts.
- Backup planner/executor that walks local directories, honors ignore globs, and streams progress.
- GitHub authorized_keys sync (`sync_keys`) with atomic append semantics.

## Building

```
cd agent
make build          # builds ./dist/backup-agent for the host
make build-all      # cross-compiles binaries for all supported targets
```

Build flags are configured in `Makefile`. Cross compilation uses `CGO_ENABLED=0`; for PTY support on macOS you may need Xcode command line tools installed.

## Configuration

The agent reads JSON configuration (default `agent-config.json`, override with `--config`). Important fields:

```json
{
  "clientId": "your-computer-hostname",
  "serverUrl": "https://example.com:8443/",
  "authToken": "shared-secret",
  "statsIntervalSec": 60,
  "admin": {
    "enableShell": true,
    "allowedCommands": ["uptime", "echo", "crontab -l"],
    "maxConcurrent": 2,
    "defaultTimeoutSec": 30
  },
  "transport": {
    "skipTlsVerify": false,
    "path": "/socket.io"
  },
  "shell": {
    "command": "/bin/bash",
    "args": ["-l"]
  }
}
```

Environment overrides:

| Variable | Effect |
| --- | --- |
| `CLIENT_ID`, `SERVER_URL`, `AUTH_TOKEN` | override identity and endpoint |
| `STATS_INTERVAL_SEC`, `HEARTBEAT_INTERVAL_SEC` | runtime tuning |
| `ADMIN_ALLOWED_COMMANDS` | comma-separated allow list |
| `AGENT_SKIP_TLS_VERIFY` | `true/false` to bypass TLS verification (dev only) |
| `CLIENT_CONFIG_PATH` | alternate config path (also `--config`) |

## Running

```
./dist/backup-agent --config /etc/backup-agent/config.json
```

The binary logs to stdout and to the file configured via `logging.file`. Service managers (systemd, supervisord, etc.) can run the binary directly with the desired config file.

## Packaging

- **Docker**: `Dockerfile.agent` builds a minimal image that copies the Go binary.
- **Install/update scripts**: `install.sh` and `update-manager.sh` now target the Go binary (see repo root).
- **pkg**: not required; the Go binary is already single-file. Use `make build-all` for release artifacts.






