# Go Agent Requirements

This document distills the runtime contract that the Go-based agent must honor so it can act as a drop-in replacement for the existing Node.js implementation. All requirements come from `docs/RFC-0001-nat-traversal.md`, `server.mjs`, `agent-config.json`, and the shipping Docker assets.

## Transport, Auth, and Configuration

- Establish an outbound TLS WebSocket to `<serverUrl>/agents` (socket.io compatible). Carry the following query params on every connect attempt:
  - `clientId`: string identifier from config.
  - `ts`: milliseconds since epoch (agent clock).
  - `sig`: hex HMAC-SHA256 over JSON `{"clientId":"<id>","ts":<ts>}` using `authToken`.
- Reject server certificates that are not trusted by the local CA bundle unless `--insecure` style opt-in is explicitly set (parity with Node's default TLS behavior).
- Configuration sources:
  - JSON file (default `agent-config.json`).
  - Environment variable overrides: `CLIENT_ID`, `SERVER_URL`, `AUTH_TOKEN`, `STATS_INTERVAL_SEC`, `HEARTBEAT_INTERVAL_SEC`, `ADMIN_ALLOWED_COMMANDS`, etc.
  - Docker entrypoint today sets `CLIENT_CONFIG_PATH`, `LOG_FILE`, `TZ`; maintain those knobs.
- Reconnect policy: exponential backoff starting at 1s, capping at 30s. Reconnect timer resets on successful `hello_ack`.

## Message Matrix

The Go agent must emit and consume the exact event names below. Payload schemas mirror the Node agent.

| Direction | Event | Payload Summary | Notes |
| --- | --- | --- | --- |
| Agent→Server | `stats` | `{ data: { cpu, mem, load, disk?, net?, ts } }` | send every `statsIntervalSec` (default 60s) |
| Agent→Server | `pong` | `{ ts }` | respond to server `ping` |
| Agent→Server | `shell_output` | `{ session, data (base64 or raw text) }` | incremental PTY data |
| Agent→Server | `shell_closed` | `{ session, code?, reason?, signal? }` | final shell state |
| Agent→Server | `backup_plan` | `{ planId, job, totalFiles, totalBytes, modifies?, files?[] }` | job echo + inspection result |
| Agent→Server | `backup_progress` | `{ planId, file?, op?, percent?, transferredBytes? }` | include `file/op` for audit |
| Agent→Server | `backup_complete` | `{ planId, ok, ms, transferredBytes }` | mark completion |
| Agent→Server | `backup_error` | `{ planId, error }` | failure details |
| Agent→Server | `admin_result` | `{ token?, command, result: { stdout, stderr, summary: { code, signal?, durationMs? }, error? } }` | consumed by cron + command flows |
| Agent→Server | `keys_sync_result` | `{ ok, user, added, ms, error? }` | ensures dashboard toasts work |
| Server→Agent | `ping` | `{ ts }` | update `lastPong` and reply with `pong` |
| Server→Agent | `shell_start` | `{ session }` | spawn PTY |
| Server→Agent | `shell_input` | `{ session, data }` | write bytes to PTY |
| Server→Agent | `shell_resize` | `{ session, cols, rows }` | adjust PTY size |
| Server→Agent | `shell_close` | `{ session }` | tear down PTY |
| Server→Agent | `admin_run` | `{ token?, cmd: { command, timeoutSec?, cwd?, env? } }` | run non-interactive command |
| Server→Agent | `backup_plan` | `{ planId, host, user, port, sourceDirs[], destRoot, ignoreGlobs[] }` | generate plan |
| Server→Agent | `backup_start` | same shape as `backup_plan` plus `planId` | execute copy/rsync |
| Server→Agent | `sync_keys` | `{ user }` | fetch GitHub authorized_keys |

Server tolerates both `t` and `type` fields. Favor `type` in new Go code but include `t` for compatibility where server dispatch expects it (e.g., `sendToClient` looks at `t || type`).

## Heartbeat and Presence

- Respond to every inbound `ping` with `pong` echoing the provided timestamp and refresh `lastPong` on both `pong` and outbound telemetry.
- Emit optional proactive `ping` if no traffic has been sent for half of `pongTimeoutSec` (90s default) to avoid idle disconnects.
- When the socket drops, ensure `lastPong` resets so reconnect logic triggers.

## Telemetry Requirements

- Gather CPU load, memory usage, and load averages using platform-specific APIs:
  - Linux: `/proc/stat`, `/proc/meminfo`.
  - Windows: `golang.org/x/sys/windows` counters.
  - macOS: `host_statistics`.
- Optional metrics (if available) should retain field names used today: `diskPercent`, `uptimeSec`, `netLatencyMs`.
- Attach ISO timestamp `ts` before sending.

## Remote Shell (PTY) Parity

- Unix: depend on `github.com/creack/pty` for fork+pty. Windows: use ConPTY (`github.com/microsoft/go-winio` or `github.com/iamacarpet/go-winpty`). Detect availability at runtime; emit `shell_closed` with `reason:"pty unavailable"` when unsupported.
- Default shell command: `/bin/bash` (Unix) or `cmd.exe` (Windows), overridable via config.
- Enforce `admin.maxConcurrent` across both PTY shells and ad-hoc admin commands.
- Support dynamic resize events; ignore invalid `cols/rows`.

## Admin Commands, Cron, and Key Sync

- `admin_run` commands must honor `allowedCommands` allowlist; reject others with `admin_result` `summary.code = 126` and `stderr` describing the policy violation.
- Cron helper commands used by `/api/client/:id/cron`:
  - `crontab -l` output returned via `admin_result.stdout`.
  - `echo <b64> | base64 -d | crontab -` executed verbatim for updates (Go agent should perform decode itself instead of relying on shell when possible, but must preserve behavior).
- Key sync: perform HTTPS GET `https://github.com/<user>.keys`, dedupe vs `~/.ssh/authorized_keys`, write additions atomically, and emit `keys_sync_result`.

## Backup Planning and Execution

- Planning step should be an rsync-style dry run (e.g., invoke `rsync --dry-run --stats` if available) or native Go walker that records file count/size respecting `ignoreGlobs`.
- Execution step must honor provided SSH target details if remote copy is still delegated to the agent; existing Node agent shells out to rsync/ssh. Preserve ability to run entirely local copies (source/dest on same host) for “pull” mode deployments.
- Persist transient state (current file, bytes transferred) so that `backup_progress` events stay frequent (<2s gaps).

## Logging and Observability

- Write structured logs to path from `LOG_FILE` (defaults to `agent.log` beside config). Rotate at ~10 MiB similar to `server.mjs`.
- Surface fatal configuration or connection errors both to stderr and log file so headless deployments notice failures.

## Node-Specific Behavior To Replace

- `node-pty` → Go PTY libraries per-OS.
- `socket.io-client` → `github.com/zishang520/socket.io-go` or native WebSocket + engine.io framing; ensure binary builds for armv7/windows.
- Shell pipelines for cron updates → native Go implementation to reduce `/bin/sh` dependency, but keep compatibility for complex operators.
- `fs/promises` JSON persistence for backup plans → integrate with Go’s `encoding/json` and atomic file writes.

Meeting all items above completes the spec-review milestone and keeps the subsequent Go scaffolding grounded in real protocol expectations.






