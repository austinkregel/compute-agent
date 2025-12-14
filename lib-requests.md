# Go dependency candidates (for user verification)

Please fetch/allow the following public modules so we can wire up the Go agent feature parity. I’ve grouped them by subsystem with the repo path we’ll reference from `go.mod`.

## Transport / Socket.io

1. `github.com/tomruk/socket.io-go` – actively maintained pure-Go socket.io v4 client that supports namespaces and Engine.IO framing; ideal for `/agents` WebSocket parity.
2. `github.com/tomruk/socket.io-go/engineio` – companion Engine.IO layer required by the socket.io client above.

## Telemetry / System stats

3. `github.com/shirou/gopsutil/v3` – cross-platform CPU/memory/load/disk telemetry library.

## PTY / Shell

4. `github.com/creack/pty` – Unix PTY spawn/resize support for shell sessions.
5. `github.com/iamacarpet/go-winpty` – Windows PTY (WinPTY/ConPTY) bindings so shells work on older Windows hosts.

## Backup helpers

6. `github.com/bmatcuk/doublestar/v4` – glob matcher compatible with rsync-style ignore rules.

## Misc utilities

7. `golang.org/x/sys` – low-level OS/syscall helpers needed by telemetry + PTY code.
8. `golang.org/x/sync/errgroup` – structured goroutine error handling for long-running subsystems.

Let me know if any of these need alternatives and I’ll adjust before wiring them into the implementation.

