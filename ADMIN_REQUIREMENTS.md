# Agent Privileges

What the agent needs from the operating system, and what each feature costs in
privilege. The short version: the agent runs unprivileged, and most of it works
that way. A handful of features need more, and each is called out below.

Running as root is a choice with consequences — `admin_run` and shell sessions
execute as whatever uid the agent has, so a root agent is a root remote-execution
service. Prefer a dedicated account and grant only what a specific feature needs.

## Works unprivileged

- **Control-plane connection.** Outbound WSS only; no bind, no privileged
  syscall. Command signature verification is pure userspace.
- **Core telemetry.** CPU, memory, load, disks, network interfaces, host info —
  all via gopsutil, reading world-readable `/proc` entries on Linux.
- **Battery and thermal.** `/sys/class/power_supply`, `/sys/class/hwmon`, and
  `/sys/class/thermal` are world-readable. GPU temperatures shell out to
  `nvidia-smi` or `rocm-smi`, which work for ordinary users on normal driver
  installs.
- **OS update checks.** `apt-get -s upgrade` is a simulation; `softwareupdate -l`
  and the Windows Update COM search are read-only queries.
- **Host health probes.** `timedatectl show` and `systemctl list-units` are
  read-only D-Bus calls. Linux only.
- **Shell sessions and command execution**, as the agent's own user.
- **Crontab.** The agent edits its own user's crontab.
- **Backups.** Local walks and copies, or `rsync` over SSH, bounded by ordinary
  filesystem permissions.
- **Directory browsing**, local and over SSH/SMB, using the agent user's own
  SSH agent or private keys.
- **SSH key sync.** Writes to the **agent process's own**
  `~/.ssh/authorized_keys`. The `user` field in the request is a GitHub username
  to fetch keys from, not a local account to write to — this never touches
  another user's home directory.
- **Log tailing.** Opens only the agent's configured log file.
- **Telephony bridge.** Outbound loopback TCP to the companion app.

## Needs more than a plain user

| Feature | Requirement | Why |
|---|---|---|
| Docker and Swarm | Read/write on the Docker socket — root or the `docker` group | Socket access is effectively root-equivalent on the host |
| Kernel log alerts | root, `CAP_SYSLOG`, or the `systemd-journal`/`adm` group | `/dev/kmsg` is restricted when `kernel.dmesg_restrict=1`; the `journalctl -k` and `dmesg` fallbacks are restricted the same way |
| Kiosk as a system service | root, or run as the desktop user | Display autodetection reads another user's `.Xauthority` and scans `/proc/<pid>/environ` for the D-Bus address |
| Self-update, variant switch | Write access to the install directory and the binary | Writes `<exe>.new` and renames over the running binary |
| Direct mode on a port below 1024 | root or `CAP_NET_BIND_SERVICE` | Ordinary bind restriction; there is no default listen address |
| Windows service install | Administrator | `CreateService` and recovery configuration. See [docs/WINDOWS_SERVICE.md](docs/WINDOWS_SERVICE.md) |

Kernel alerts degrade rather than fail: unprivileged, the monitor runs but sees
less.

Nothing in the agent escalates privilege. There is no setuid path, no capability
request, no `pkexec` or `doas`, and no Go code invokes `sudo` — whatever the agent
does, it does directly with its own uid. You can put `sudo` in the allowlist to
grant a specific privileged command, subject to the tokenizing rules below.

## Command execution

Two entry points — `admin_run` from the control plane and `exec_request` from a
direct-mode client — share the same guards, applied in order:

1. **Rate limit.** A fixed window shared across command execution and shell
   starts. Disabled when `admin.rateLimitMax` is 0; rejects with exit code 429.
2. **Shell metacharacters.** `;`, `|`, `&&`, `||`, backticks, `$`, and newlines
   are rejected outright, including inside quotes.
3. **Tokenization.** Quote- and escape-aware, with no variable expansion and no
   globbing.
4. **Allowlist.** Prefix match on normalized tokens. **An empty allowlist denies
   everything** — absence of a policy is not permission.
5. **Concurrency slot**, sized by `admin.maxConcurrent` (default 1).
6. **Execution with explicit argv.** `exec.CommandContext` with the tokens —
   never `/bin/sh -c`.
7. **Environment sanitization.** Only `PATH`, `HOME`, `USER`, `LANG`, `LC_ALL`,
   `TERM`, `TMPDIR`, `TEMP`, `SystemRoot`, and `ComSpec` survive, and only if
   already set. The agent's own environment is never passed through.
8. **Working directory validation** against `admin.allowedCwds`. An empty list
   means **any** request specifying a cwd is rejected.

Two things worth knowing:

**Signature-based bypass.** If argv[0] is an absolute path to a file with a valid
adjacent `.minisig` signature from a pinned key, it runs regardless of the
allowlist. `admin.trustedSigners` holds those keys and ships with one built-in
default. Set `admin.signatureTrustStrict` to disable the mechanism.

**The token check covers `admin_run` only.** `admin.requireToken` and
`admin.commandToken` gate that one path. `exec_request`, `shell_start`, backups,
key sync, and file operations rely entirely on command-signature verification.

**Interactive shells are not allowlisted.** `admin.enableShell` is the whole gate;
the command comes from `shell.command`/`shell.args`. Shell access is an
authorization decision made at the control plane, not a command-filtering one.

## File operations

File operations from the control plane are confined by a path policy, not by
`dirBrowse.allowedRoots` — that setting applies to directory listing and to
`exec_request` working directories.

The policy hard-denies `/dev`, `/proc`, `/sys`, and `/run`. It requires an
explicit `force` flag for `/bin`, `/sbin`, `/usr`, `/lib*`, `/boot`, `/snap`,
`/var/lib`, `/var/cache`, `C:\Windows`, and `C:\Program Files*`. Everything else
is bounded only by the process's uid — which is the real argument for not
running as root.

## Files the agent writes

| What | Mode |
|---|---|
| Log file and its directory | dir `0700`, file `0600`, rotating at 10 MiB |
| Backup plan and progress state | dir `0700`, files `0600`, written atomically |
| Backup destination files | dir `0700`, file `0600` |
| `~/.ssh` and `authorized_keys` | dir `0700`, file `0600`, atomic rename |
| Kiosk layout and content stores | `0600`, in the process working directory |
| Uploaded files | caller-supplied mode, parent directories `0755` |
| Updated binaries | `0755` |

The agent never writes its own config file; installers do that.

## Platform differences

`GOOS=android` also satisfies Go's `linux` build tag, which is why several files
carry explicit `!android` guards.

- **Linux** has everything. Kernel alerts default on here and only here.
- **macOS** has no kernel alerts and no battery collector. Thermal readings come
  from gopsutil alone. Service management is not supported.
- **Windows** has no kernel alerts. Battery comes from WMI and thermal from
  OpenHardwareMonitor plus gopsutil. `chmod` is rejected outright. Shells use
  pipes rather than a PTY. Updates swap via an `.old` rename cleaned up at next
  startup.
- **Android** compiles out the sysfs battery and thermal collectors and reads
  both from the companion app instead, over the `host.telemetry` bridge op. GPU
  temperatures and the kiosk WebView are stubbed.
- **CGO disabled** — which is how all release binaries and the container image
  are built — compiles out the kiosk WebView entirely; the agent reports itself
  as the `headless` variant.

## Installation

The Linux installer requires root: it installs supervisord through the system
package manager, creates `/opt/agent`, writes a supervisor program file, and
restarts the supervisor. **Supervisord, not systemd, is the supervision
mechanism** — no systemd unit ships in this repository. systemd is only ever read
from, for telemetry.

If the `backup-agent` user does not exist, the installer warns and the agent runs
as root.

Windows service subcommands (`service install|uninstall|start|stop|status`) need
an elevated prompt. The service runs in Session 0, so kiosk mode is unavailable
under it.

On Android the agent runs inside the companion app's foreground service, launched
from the read-only native library directory because API 29+ forbids executing
from an app's writable data directory. Its permissions are ordinary app
permissions; no rooted device is involved.

The container image runs as root deliberately — it reads host telemetry, executes
allowlisted commands, and talks to the Docker daemon when the socket is mounted.

## Config reference

Privilege- and safety-relevant settings, with defaults:

| Key | Default | Effect |
|---|---|---|
| `admin.enableShell` | `false` | Interactive PTY sessions |
| `admin.allowedCommands` | none | **Empty denies everything** |
| `admin.allowlistMode` | `merge` | `merge` unions local and control-plane lists; `cp-authoritative` takes the pushed list verbatim |
| `admin.allowedCwds` | none | **Empty rejects any request naming a cwd** |
| `admin.maxConcurrent` | `1` | Concurrent commands and shells |
| `admin.defaultTimeoutSec` | `30` | Per-command timeout |
| `admin.requireToken` | `false` | Per-request token on `admin_run` only |
| `admin.rateLimitMax` | `0` | 0 disables rate limiting |
| `admin.rateLimitWindowSec` | `60` when limiting | Window length |
| `admin.trustedSigners` | one built-in key | Signature-based allowlist bypass |
| `admin.signatureTrustStrict` | `false` | Disables that bypass |
| `backup.allowedSourceRoots` | none | Empty is unrestricted |
| `backup.allowedDestRoots` | none | Empty is unrestricted |
| `dirBrowse.allowedRoots` | none | Empty is unrestricted for listing |
| `dirBrowse.sshHostKeyPolicy` | `known_hosts` | Or `insecure_accept_any` |
| `transport.skipTlsVerify` | `false` | Env `AGENT_SKIP_TLS_VERIFY` |
| `transport.maxClockSkewSec` | `300` | Command freshness window |
| `docker.enabled` | `true` | Env `AGENT_DOCKER_ENABLED` |
| `directMode.enabled` | `false` | Inbound listener; refuses to start without cert, listen address, and roots |

Note the asymmetry in the "empty means" column: the exec allowlist and
`allowedCwds` fail closed, while the browse and backup root lists fail open. Set
the latter explicitly if the agent runs anywhere untrusted.

Config path is `CLIENT_CONFIG_PATH`, defaulting to `./agent-config.json`. Values
load as defaults, then the JSON file, then environment overrides:
`CLIENT_ID`, `SERVER_URL`, `AUTH_TOKEN`, `STATS_INTERVAL_SEC`,
`HEARTBEAT_INTERVAL_SEC`, `UPDATE_CHECK_ENABLED`,
`UPDATE_CHECK_INTERVAL_HOURS`, `PONG_TIMEOUT_SEC`, `OHM_PORT`,
`ADMIN_ALLOWED_COMMANDS`, `AGENT_SKIP_TLS_VERIFY`, `AGENT_DOCKER_ENABLED`,
`AGENT_DOCKER_SOCKET`, and `LOG_FILE`.

The container entrypoint understands more names and renders them into the JSON
before the agent starts; those are not read by the agent itself.
