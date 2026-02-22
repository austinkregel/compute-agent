# Go Agent

This directory contains the Go server monitoring agent and produces a single self-contained binary that runs on Linux (amd64/arm64/armv7), macOS (amd64/arm64), and Windows (amd64).

## Features

- Socket.IO control-plane connection with HMAC (`clientId`, `ts`, `sig`) auth.
- Periodic telemetry (`cpu`, `mem`, `load`, `uptime`) via gopsutil.
- OS update availability telemetry (best-effort) with periodic 12h refresh + manual refresh trigger from dashboard.
- Remote shell with PTY (`creack/pty` on Unix, pipe fallback on Windows).
- `admin_run` command executor with allow-list and per-command timeouts.
- Backup planner/executor that walks local directories, honors ignore globs, and streams progress.
- GitHub authorized_keys sync (`sync_keys`) with atomic append semantics.

## Building

```bash
cd agent
make build          # builds ./dist/backup-agent with kiosk support (CGO_ENABLED=1)
make build-headless # builds ./dist/backup-agent without kiosk (CGO_ENABLED=0)
make build-all      # cross-compiles headless binaries for all supported targets
```

Build flags are configured in `Makefile`. Cross compilation uses `CGO_ENABLED=0`; for PTY support on macOS you may need Xcode command line tools installed.

## Release Artifacts

The CI pipeline produces two variants for each platform/architecture combination:

- **Headless**: For servers, VMs, containers, and headless environments. Built with `CGO_ENABLED=0` (no GUI dependencies).
- **Kiosk**: For desktop/display machines with kiosk mode support. Built with `CGO_ENABLED=1` (requires GUI libraries).

### Linux

| Architecture | Headless | Kiosk |
| --- | --- | --- |
| x86_64 (amd64) | `backup-agent-linux-amd64` | `backup-agent-linux-amd64-kiosk` |
| ARM64 | `backup-agent-linux-arm64` | `backup-agent-linux-arm64-kiosk` |
| ARM (32-bit) | `backup-agent-linux-arm` | _(build locally)_ |

**Kiosk runtime requirements**:
```bash
sudo apt install libgtk-3-0 libwebkit2gtk-4.1-0  # Ubuntu/Debian
```

### macOS

| Architecture | Headless | Kiosk |
| --- | --- | --- |
| Intel (amd64) | `backup-agent-darwin-amd64` | `backup-agent-darwin-amd64-kiosk` |
| Apple Silicon (arm64) | `backup-agent-darwin-arm64` | `backup-agent-darwin-arm64-kiosk` |

No additional runtime requirements (WebKit is included with macOS).

### Windows

| Architecture | Headless | Kiosk |
| --- | --- | --- |
| x86_64 (amd64) | `backup-agent-windows-amd64.exe` | `backup-agent-windows-amd64-kiosk.exe` |

**Kiosk runtime requirements**: Microsoft Edge browser (included with Windows 10/11).

## Configuration

The agent reads JSON configuration (default `agent-config.json`, override with `--config`). Important fields:

```json
{
  "clientId": "your-computer-hostname",
  "serverUrl": "https://example.com:8443/",
  "authToken": "shared-secret",
  "statsIntervalSec": 60,
  "updateCheckEnabled": true,
  "updateCheckIntervalHours": 12,
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
  "openHardwareMonitorPort": 8085,
  "shell": {
    "command": "/bin/bash",
    "args": ["-l"],
    "idleTimeoutSec": 60
  },
  "dirBrowse": {
    "allowedRoots": [],
    "sshHostKeyPolicy": "known_hosts",
    "smbProfiles": {
      "nas": {
        "username": "WORKGROUP\\\\backup",
        "password": "REDACTED",
        "domain": "WORKGROUP"
      }
    }
  }
}
```

Environment overrides:

| Variable | Effect |
| --- | --- |
| `CLIENT_ID`, `SERVER_URL`, `AUTH_TOKEN` | override identity and endpoint |
| `STATS_INTERVAL_SEC`, `HEARTBEAT_INTERVAL_SEC` | runtime tuning |
| `UPDATE_CHECK_ENABLED`, `UPDATE_CHECK_INTERVAL_HOURS` | OS update check tuning |
| `ADMIN_ALLOWED_COMMANDS` | comma-separated allow list |
| `AGENT_SKIP_TLS_VERIFY` | `true/false` to bypass TLS verification (dev only) |
| `OHM_PORT` | override OpenHardwareMonitor HTTP port (Windows thermal) |
| `CLIENT_CONFIG_PATH` | alternate config path (also `--config`) |

### Windows thermal telemetry (OpenHardwareMonitor)

- OpenHardwareMonitor’s Remote Web Server must be enabled (Options → Remote Web Server).
- The agent queries `http://localhost:<openHardwareMonitorPort>/data.json` (default `8085`).
- Set `openHardwareMonitorPort` in config or `OHM_PORT` env if the port differs.
- If OHM is unavailable, telemetry falls back to gopsutil sensors (best-effort).

## OS update checks (host maintenance insight)

The agent reports a compact update status summary under `stats.updates` and `stats.securityPatchStatus`:

- **Linux (Debian/Ubuntu)**: uses `apt-get -s upgrade` to count upgradable packages (does not run `apt-get update`), and checks `/var/run/reboot-required` for reboot indication.
- **macOS**: uses `softwareupdate -l` (counts labels; detects restart action).
- **Windows**: queries Windows Update via COM from PowerShell; also checks common reboot-pending registry markers.

Notes:
- These checks are **best-effort** and may require appropriate permissions / services enabled (especially on Windows/macOS).
- The dashboard can request an immediate refresh via the “Check now” button; otherwise the agent refreshes about every 12 hours by default.

## Running

```
./dist/backup-agent --config /etc/backup-agent/config.json
```

The binary logs to stdout and to the file configured via `logging.file`. Service managers (systemd, supervisord, etc.) can run the binary directly with the desired config file.

## Kiosk Mode

Kiosk mode enables the agent to display a fullscreen window that can be controlled remotely from the dashboard. This is useful for digital signage, status displays, or interactive kiosks.

When enabled, the agent opens a native WebView window that displays content controlled by the dashboard.

### Which Binary to Use

- **Headless binary** (`backup-agent-linux-amd64`, etc.): Use for servers, VMs, containers, or any environment without a display. If kiosk is enabled in config, the agent will log a warning and continue running without kiosk functionality.

- **Kiosk binary** (`backup-agent-linux-amd64-kiosk`, etc.): Use for machines with displays where you want kiosk functionality. Requires GUI runtime libraries on Linux.

### Local Build Requirements

If building locally with kiosk support (`make build`):

| Platform | Build Dependencies |
| --- | --- |
| **Linux** | `apt install libgtk-3-dev libwebkit2gtk-4.1-dev` |
| **macOS** | Xcode command line tools (WebKit included) |
| **Windows** | MinGW-w64 or MSVC |

### Enabling Kiosk Mode

Add the kiosk configuration to `agent-config.json`:

```json
{
  "kiosk": {
    "enabled": true,
    "listenAddr": "127.0.0.1:0",
    "fullscreen": true
  }
}
```

| Field | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Enable kiosk mode |
| `listenAddr` | `127.0.0.1:0` | Local HTTP/WS server address (ephemeral port by default) |
| `fullscreen` | `true` | Open window in fullscreen mode |

### Dashboard Control

When kiosk mode is enabled and the agent is connected, the dashboard's Actions view shows kiosk controls:

- **Blank**: Show a blank screen
- **Message**: Display a title and message
- **URL**: Load a web page in an iframe

The kiosk status indicator shows:
- Green dot: Kiosk connected and displaying content
- Yellow dot: Kiosk running but not connected
- Gray dot: Kiosk offline or not enabled

### Security

- The local kiosk HTTP/WS server binds to localhost by default
- WebSocket connections require a random session token generated at startup
- All kiosk commands from the dashboard are signed (same mechanism as shell commands)
- URL content is restricted to `http://` and `https://` schemes only

## Packaging

- **Docker**: `Dockerfile.agent` builds a minimal image that copies the Go binary.
- **Install/update scripts**: `install.sh` and `update-manager.sh` now target the Go binary (see repo root).
- **pkg**: not required; the Go binary is already single-file. Use `make build-all` for release artifacts.







