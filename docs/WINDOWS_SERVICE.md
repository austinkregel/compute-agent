# Running the agent as a Windows service (headless)

On Linux/macOS the agent is supervised by systemd/supervisord and self-updates
by re-`exec`ing in place. Windows has no equivalent, so the headless agent runs
as a native Windows service under the Service Control Manager (SCM). The SCM
keeps it alive across crashes and self-updates.

> Kiosk mode is **not** covered here. A Windows service runs in Session 0, which
> has no interactive desktop, so a service cannot display the kiosk browser. Run
> kiosk machines from an interactive logon session instead (auto-login + a logon
> Scheduled Task).

## Install

Run from an elevated (Administrator) prompt. Use absolute paths — a service's
working directory defaults to `C:\Windows\System32`, so relative config/log
paths resolve there.

```
backup-agent.exe service install --config C:\ProgramData\backup-agent\agent-config.json
backup-agent.exe service start
```

`install` registers the service `BackupAgent` with:

- **Automatic (delayed) start** — comes up after boot.
- **Recovery actions** — restart after 5s, 5s, then 30s, with the counter
  resetting daily. This is what brings the agent back after a crash.
- **Restart on non-crash failures** — so an exit code from a self-update also
  triggers a restart onto the new binary.

The absolute `--config` path you pass at install time is baked into the
service's command line.

## Manage

```
backup-agent.exe service status      # not installed | running | stopped | ...
backup-agent.exe service stop
backup-agent.exe service start
backup-agent.exe service uninstall   # stops then removes the service
```

## How update-restart works under the service

When the agent self-updates it stages the new binary, then — because it detects
it is running as a service (`svc.IsWindowsService`) — exits with code `10`
instead of trying to respawn itself. The SCM sees the process terminate and its
recovery action relaunches the service, which starts the freshly staged binary.
No detached-child juggling, no locked-file races.

When the agent is run interactively (double-clicked, or from a console) it is
not a service, so it falls back to spawning a replacement process in its own
process group and exiting.
