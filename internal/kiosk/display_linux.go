//go:build linux

package kiosk

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// ensureDisplayEnv auto-detects and sets X11/Wayland environment variables
// when the agent runs as a system service (supervisord, systemd, etc.).
//
// On boot the graphical session may not be ready yet (auto-login hasn't
// completed). This function retries for up to ~90 seconds, polling every
// 5 seconds, to give the desktop session time to start.
func ensureDisplayEnv() {
	// X11: fully configured
	if os.Getenv("DISPLAY") != "" && os.Getenv("XAUTHORITY") != "" {
		fmt.Fprintf(os.Stderr, "[kiosk] display env already set: DISPLAY=%s XAUTHORITY=%s\n",
			os.Getenv("DISPLAY"), os.Getenv("XAUTHORITY"))
		return
	}
	// Wayland: fully configured
	if os.Getenv("WAYLAND_DISPLAY") != "" && os.Getenv("XDG_RUNTIME_DIR") != "" {
		fmt.Fprintf(os.Stderr, "[kiosk] display env already set: WAYLAND_DISPLAY=%s XDG_RUNTIME_DIR=%s\n",
			os.Getenv("WAYLAND_DISPLAY"), os.Getenv("XDG_RUNTIME_DIR"))
		return
	}

	const maxAttempts = 18 // 18 × 5s = 90s
	const pollInterval = 5 * time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			fmt.Fprintf(os.Stderr, "[kiosk] waiting for graphical session (attempt %d/%d, next check in %s)...\n",
				attempt, maxAttempts, pollInterval)
			time.Sleep(pollInterval)
		}

		found := tryDetectSession()
		if found {
			return
		}
	}

	fmt.Fprintf(os.Stderr, "[kiosk] FATAL: no graphical session detected after %d attempts (%s)\n",
		maxAttempts, time.Duration(maxAttempts)*pollInterval)
	fmt.Fprintf(os.Stderr, "[kiosk]   DISPLAY=%q XAUTHORITY=%q WAYLAND_DISPLAY=%q XDG_RUNTIME_DIR=%q\n",
		os.Getenv("DISPLAY"), os.Getenv("XAUTHORITY"),
		os.Getenv("WAYLAND_DISPLAY"), os.Getenv("XDG_RUNTIME_DIR"))
	fmt.Fprintf(os.Stderr, "[kiosk]   Ensure the machine has a graphical desktop session (X11 or Wayland).\n")
	fmt.Fprintf(os.Stderr, "[kiosk]   If using auto-login, verify the display manager is starting correctly.\n")
}

// tryDetectSession attempts to find and configure the display environment.
// Returns true if a usable session was found.
func tryDetectSession() bool {
	// Strategy 1: loginctl
	out, err := exec.Command("loginctl", "list-sessions", "--no-legend").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[kiosk] loginctl unavailable (%v), trying fallback detection\n", err)
		return tryDetectSessionFallback()
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	fmt.Fprintf(os.Stderr, "[kiosk] loginctl found %d session(s)\n", len(lines))

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		sessionID := fields[0]

		propOut, err := exec.Command("loginctl", "show-session", sessionID,
			"-p", "Type", "-p", "Display", "-p", "User", "-p", "Name", "-p", "State", "-p", "Active").Output()
		if err != nil {
			continue
		}

		var sessType, display, uid, user, state, active string
		for _, prop := range strings.Split(string(propOut), "\n") {
			parts := strings.SplitN(strings.TrimSpace(prop), "=", 2)
			if len(parts) != 2 {
				continue
			}
			switch parts[0] {
			case "Type":
				sessType = parts[1]
			case "Display":
				display = parts[1]
			case "User":
				uid = parts[1]
			case "Name":
				user = parts[1]
			case "State":
				state = parts[1]
			case "Active":
				active = parts[1]
			}
		}

		fmt.Fprintf(os.Stderr, "[kiosk]   session %s: type=%s user=%s(%s) display=%q state=%s active=%s\n",
			sessionID, sessType, user, uid, display, state, active)

		if sessType != "x11" && sessType != "wayland" {
			continue
		}

		if sessType == "x11" {
			if os.Getenv("DISPLAY") == "" {
				if display != "" {
					os.Setenv("DISPLAY", display)
				} else {
					os.Setenv("DISPLAY", ":0")
				}
			}
			if os.Getenv("XAUTHORITY") == "" {
				setXauthority(user, uid)
			}
			setSessionBusAndRuntime(uid)
			fmt.Fprintf(os.Stderr, "[kiosk] detected X11 session for %s: DISPLAY=%s XAUTHORITY=%s DBUS_SESSION_BUS_ADDRESS=%s XDG_RUNTIME_DIR=%s\n",
				user, os.Getenv("DISPLAY"), os.Getenv("XAUTHORITY"),
				os.Getenv("DBUS_SESSION_BUS_ADDRESS"), os.Getenv("XDG_RUNTIME_DIR"))
			return true
		}

		// Wayland session — GTK apps use XWayland, so also set DISPLAY
		if os.Getenv("WAYLAND_DISPLAY") == "" {
			wd := display
			if wd == "" {
				wd = "wayland-0"
			}
			os.Setenv("WAYLAND_DISPLAY", wd)
		}
		if os.Getenv("XDG_RUNTIME_DIR") == "" && uid != "" {
			os.Setenv("XDG_RUNTIME_DIR", "/run/user/"+uid)
		}
		if os.Getenv("DISPLAY") == "" {
			os.Setenv("DISPLAY", ":0")
		}
		if os.Getenv("XAUTHORITY") == "" {
			setXauthority(user, uid)
		}
		setSessionBusAndRuntime(uid)
		fmt.Fprintf(os.Stderr, "[kiosk] detected Wayland session for %s: DISPLAY=%s WAYLAND_DISPLAY=%s XDG_RUNTIME_DIR=%s XAUTHORITY=%s DBUS_SESSION_BUS_ADDRESS=%s\n",
			user, os.Getenv("DISPLAY"), os.Getenv("WAYLAND_DISPLAY"),
			os.Getenv("XDG_RUNTIME_DIR"), os.Getenv("XAUTHORITY"),
			os.Getenv("DBUS_SESSION_BUS_ADDRESS"))
		return true
	}

	return tryDetectSessionFallback()
}

func setXauthority(user, uid string) {
	for _, candidate := range xauthorityCandidates(user, uid) {
		if _, err := os.Stat(candidate); err == nil {
			os.Setenv("XAUTHORITY", candidate)
			return
		}
		fmt.Fprintf(os.Stderr, "[kiosk]   tried XAUTHORITY=%s (not found)\n", candidate)
	}
	fmt.Fprintf(os.Stderr, "[kiosk]   WARNING: could not find .Xauthority file for user %s (uid %s)\n", user, uid)
}

// tryDetectSessionFallback scans the filesystem when loginctl is unavailable.
func tryDetectSessionFallback() bool {
	found := false

	if os.Getenv("DISPLAY") == "" {
		entries, err := os.ReadDir("/tmp/.X11-unix")
		if err == nil {
			for _, e := range entries {
				name := e.Name()
				if strings.HasPrefix(name, "X") {
					d := ":" + name[1:]
					fmt.Fprintf(os.Stderr, "[kiosk] fallback: found X socket %s → DISPLAY=%s\n", name, d)
					os.Setenv("DISPLAY", d)
					found = true
					break
				}
			}
		}
	} else {
		found = true
	}

	if os.Getenv("DISPLAY") != "" && os.Getenv("XAUTHORITY") == "" {
		homes, err := os.ReadDir("/home")
		if err == nil {
			for _, h := range homes {
				if !h.IsDir() {
					continue
				}
				candidate := filepath.Join("/home", h.Name(), ".Xauthority")
				if _, err := os.Stat(candidate); err == nil {
					fmt.Fprintf(os.Stderr, "[kiosk] fallback: found XAUTHORITY=%s\n", candidate)
					os.Setenv("XAUTHORITY", candidate)
					break
				}
			}
		}
	}

	return found && os.Getenv("DISPLAY") != "" && os.Getenv("XAUTHORITY") != ""
}

// xauthorityCandidates returns paths where .Xauthority commonly lives.
func xauthorityCandidates(user, uid string) []string {
	var out []string
	if user != "" {
		out = append(out, filepath.Join("/home", user, ".Xauthority"))
	}
	if uid != "" {
		out = append(out,
			filepath.Join("/run/user", uid, "gdm", "Xauthority"),
			filepath.Join("/run/user", uid, ".Xauthority"),
		)
	}
	return out
}

// setSessionBusAndRuntime sets DBUS_SESSION_BUS_ADDRESS and XDG_RUNTIME_DIR
// for the detected user session. WebKit2GTK requires D-Bus for its multi-process
// architecture (network process, web process, etc.).
func setSessionBusAndRuntime(uid string) {
	if uid == "" {
		return
	}

	runtimeDir := "/run/user/" + uid
	if os.Getenv("XDG_RUNTIME_DIR") == "" {
		if info, err := os.Stat(runtimeDir); err == nil && info.IsDir() {
			os.Setenv("XDG_RUNTIME_DIR", runtimeDir)
			fmt.Fprintf(os.Stderr, "[kiosk]   set XDG_RUNTIME_DIR=%s\n", runtimeDir)
		}
	}

	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		busSocket := filepath.Join(runtimeDir, "bus")
		if _, err := os.Stat(busSocket); err == nil {
			addr := "unix:path=" + busSocket
			os.Setenv("DBUS_SESSION_BUS_ADDRESS", addr)
			fmt.Fprintf(os.Stderr, "[kiosk]   set DBUS_SESSION_BUS_ADDRESS=%s\n", addr)
			return
		}

		// Fallback: scan /proc for the user's dbus-daemon and extract address
		addr := findDBusAddrFromProc(uid)
		if addr != "" {
			os.Setenv("DBUS_SESSION_BUS_ADDRESS", addr)
			fmt.Fprintf(os.Stderr, "[kiosk]   set DBUS_SESSION_BUS_ADDRESS=%s (from /proc)\n", addr)
			return
		}

		fmt.Fprintf(os.Stderr, "[kiosk]   WARNING: could not find DBUS_SESSION_BUS_ADDRESS for uid %s\n", uid)
	}
}

// findDBusAddrFromProc reads /proc/*/environ to find DBUS_SESSION_BUS_ADDRESS
// from a process owned by the target uid. This handles cases where the bus
// socket isn't at the standard path.
func findDBusAddrFromProc(uid string) string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return ""
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		if pid[0] < '1' || pid[0] > '9' {
			continue
		}

		// Check process owner
		info, err := os.Stat(filepath.Join("/proc", pid))
		if err != nil {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if fmt.Sprintf("%d", stat.Uid) != uid {
			continue
		}

		// Read environ for DBUS_SESSION_BUS_ADDRESS
		envData, err := os.ReadFile(filepath.Join("/proc", pid, "environ"))
		if err != nil {
			continue
		}
		for _, entry := range strings.Split(string(envData), "\x00") {
			if strings.HasPrefix(entry, "DBUS_SESSION_BUS_ADDRESS=") {
				return strings.TrimPrefix(entry, "DBUS_SESSION_BUS_ADDRESS=")
			}
		}
	}
	return ""
}
