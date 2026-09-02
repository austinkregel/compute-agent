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
make build-android  # android/arm64 for phone-class agents (needs NDK; see below)
```

Build flags are configured in `Makefile`. Cross compilation uses `CGO_ENABLED=0`; for PTY support on macOS you may need Xcode command line tools installed.

### Android (phone-class agents)

`build-android` is the one target that needs CGO and a cross-compiler, so it is
not part of `build-all`. Install the NDK once:

```bash
../app/setup-android-sdk.sh --with-ndk
```

CGO is needed for **DNS**, not for the kiosk WebView. With `CGO_ENABLED=0` Go
uses its pure resolver, which reads `/etc/resolv.conf` — a file Android has no
equivalent of. The agent then falls back to `127.0.0.1:53`, nothing is
listening there, and every hostname lookup fails with
`connection refused`. Building `GOOS=android` against the NDK links bionic's
resolver, which queries netd and so honours the device's real DNS, including
Wi-Fi, cellular, VPN and Private DNS.

Because `GOOS=android` also satisfies Go's `linux` build tag, the GTK WebView
files in `internal/kiosk` carry explicit `!android` guards; the kiosk stub is
used on Android instead.

Deploying without root (binaries may be executed from `/data/local/tmp`):

```bash
adb push dist/backup-agent-android-arm64 /data/local/tmp/backup-agent/backup-agent
adb shell chmod 755 /data/local/tmp/backup-agent/backup-agent
adb push agent-config.json /data/local/tmp/backup-agent/agent-config.json
adb shell chmod 600 /data/local/tmp/backup-agent/agent-config.json
adb shell 'cd /data/local/tmp/backup-agent && \
  setsid ./backup-agent --config ./agent-config.json </dev/null >runtime.log 2>&1 &'
```

Set `telephony.enabled` plus the `companionToken` shown by the companion app
(see `app/README.md`) to expose the phone's SMS to the control plane.

Battery and thermal telemetry come from the companion app rather than sysfs.
`battery_android.go` and `thermal_android.go` replace the sysfs collectors
(which are excluded from the build via `linux && !android`) and read through
`telemetry.SetHostProvider`, wired to the companion in `agent/internal/app`.
This is not a fallback: an app-uid process cannot open `/sys/class/power_supply`
or `/sys/class/thermal` on a stock device at all, so the companion is the only
path to that data — and it yields more than sysfs would, including charge
cycle count. The Docker probe still finds no daemon and degrades gracefully.

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
# Ubuntu 22.04+ / Debian 12+
sudo apt install libgtk-3-0 libwebkit2gtk-4.1-0

# Ubuntu 20.04 / Debian 11 (requires special build, see below)
sudo apt install libgtk-3-0 libwebkit2gtk-4.0-37
```

> **Note**: The prebuilt kiosk binaries are compiled against webkit2gtk-4.1 (Ubuntu 22.04+).
> For older distros with webkit2gtk-4.0, you need to build locally with `make build-kiosk-gtk40`.

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

## Running in Docker

The release workflow publishes `ghcr.io/austinkregel/compute-agent` for
`linux/amd64`, `linux/arm64` and `linux/arm/v7`. Nothing needs to be configured
on disk first — the entrypoint renders a config from environment variables:

```bash
docker run -d --name compute-agent --restart unless-stopped \
  --network host --pid host \
  -v compute-agent-data:/data \
  -e SERVER_URL=wss://your-server/ws/agent \
  -e AUTH_TOKEN=your-token \
  -e CLIENT_ID=your-machine \
  ghcr.io/austinkregel/compute-agent:latest
```

`--network host` and `--pid host` are what make the reported telemetry describe
the *host* rather than the container. `CLIENT_ID` should be set explicitly:
without it the agent falls back to the container hostname, which changes on
every recreate and registers as a new machine in the fleet.

A ready-made compose file lives at [`docker/compose.yaml`](docker/compose.yaml).

### Configuration sources

`docker/entrypoint.sh` picks a config in this order:

| Source | When it wins |
| --- | --- |
| `AGENT_CONFIG_JSON` | Set — the value is a complete config document, written verbatim |
| `/data/options.json` | Present — Home Assistant Supervisor options (the add-on path) |
| `$CLIENT_CONFIG_PATH` | The file exists and this script did not write it |
| Environment variables | Otherwise |

A config the entrypoint generated is marked with a sibling `.generated` file, so
changing an environment variable and restarting re-renders it, while a config
you mounted yourself is never overwritten. Whichever source wins, the agent's
own environment overrides (`SERVER_URL`, `AUTH_TOKEN`, `CLIENT_ID`,
`STATS_INTERVAL_SEC`, … — see `applyEnvOverrides` in `pkg/config/config.go`)
still apply on top.

### Environment variables

`SERVER_URL` and `AUTH_TOKEN` are required. Beyond the ones the agent itself
reads, the entrypoint understands `LOG_LEVEL`, `TRANSPORT_PATH`,
`MAX_CLOCK_SKEW_SEC`, `ENABLE_SHELL`, `SHELL_IDLE_TIMEOUT_SEC`,
`ADMIN_ALLOWED_CWDS`, `ADMIN_MAX_CONCURRENT`, `ADMIN_DEFAULT_TIMEOUT_SEC`,
`REQUIRE_COMMAND_TOKEN`, `COMMAND_TOKEN`, `ENABLE_ALERTS`,
`ALERTS_SCAN_INTERVAL_SEC`, `BACKUP_SOURCE_ROOTS`, `BACKUP_DEST_ROOTS` and
`DIRBROWSE_ROOTS` (the last three are comma-separated lists).

File access defaults deliberately narrow: only `/data`, plus `/host` when the
host filesystem is mounted there (`-v /:/host:ro`). Widen it explicitly rather
than by mounting more into the container.

Self-update is disabled in the container: the binary lives in a read-only image
layer, so a new agent version arrives as a new image.

### Home Assistant

The [`ha-compute-agent`](https://github.com/austinkregel/ha-compute-agent)
add-on is this same image — the Supervisor writes `/data/options.json` and the
entrypoint renders it, mapping the add-on's volumes (`/homeassistant`, `/ssl`,
`/media`, `/backup`, `/share`) into the backup and directory-browse roots.

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
| **Linux (22.04+)** | `apt install libgtk-3-dev libwebkit2gtk-4.1-dev` |
| **Linux (20.04)** | `apt install libgtk-3-dev libwebkit2gtk-4.0-dev` then use `make build-kiosk-gtk40` |
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

- **Docker**: `Dockerfile` builds the published `ghcr.io/austinkregel/compute-agent` image (see [Running in Docker](#running-in-docker)); `make docker-build` builds it locally.
- **Install/update scripts**: `install.sh` and `update-manager.sh` now target the Go binary (see repo root).
- **pkg**: not required; the Go binary is already single-file. Use `make build-all` for release artifacts.







