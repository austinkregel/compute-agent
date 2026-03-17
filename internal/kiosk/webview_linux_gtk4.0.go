//go:build cgo && linux && webkit_4_0

package kiosk

/*
#cgo linux pkg-config: gtk+-3.0 webkit2gtk-4.0
#cgo linux CXXFLAGS: -DWEBVIEW_GTK -std=c++11
#cgo linux LDFLAGS: -ldl

#include <gtk/gtk.h>
#include <webkit2/webkit2.h>
#include <stdlib.h>

static GtkWidget *window = NULL;
static GtkWidget *webview = NULL;
static int init_error = 0;

static int init_webview(const char *title, int width, int height, int fullscreen) {
    if (!gtk_init_check(NULL, NULL)) {
        init_error = 1;
        return 1;
    }

    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    if (window == NULL) {
        init_error = 2;
        return 2;
    }

    gtk_window_set_title(GTK_WINDOW(window), title);
    gtk_window_set_default_size(GTK_WINDOW(window), width, height);

    if (fullscreen) {
        gtk_window_fullscreen(GTK_WINDOW(window));
    }

    webview = webkit_web_view_new();
    if (webview == NULL) {
        init_error = 3;
        return 3;
    }

    gtk_container_add(GTK_CONTAINER(window), webview);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    return 0;
}

static void navigate(const char *url) {
    if (webview != NULL) {
        webkit_web_view_load_uri(WEBKIT_WEB_VIEW(webview), url);
    }
}

// Thread-safe navigation: can be called from any goroutine while gtk_main runs.
static gboolean nav_idle_cb(gpointer data) {
    char *url = (char *)data;
    if (webview != NULL) {
        webkit_web_view_load_uri(WEBKIT_WEB_VIEW(webview), url);
    }
    g_free(url);
    return G_SOURCE_REMOVE;
}

static void navigate_async(const char *url) {
    g_idle_add(nav_idle_cb, g_strdup(url));
}

static void run_webview() {
    if (window != NULL) {
        gtk_widget_show_all(window);
        gtk_main();
    }
}

static int get_init_error() {
    return init_error;
}
*/
import "C"
import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"
)

// webviewAvailable indicates whether WebView support is compiled in.
const webviewAvailable = true

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
			fmt.Fprintf(os.Stderr, "[kiosk] detected X11 session for %s: DISPLAY=%s XAUTHORITY=%s\n",
				user, os.Getenv("DISPLAY"), os.Getenv("XAUTHORITY"))
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
		fmt.Fprintf(os.Stderr, "[kiosk] detected Wayland session for %s: DISPLAY=%s WAYLAND_DISPLAY=%s XDG_RUNTIME_DIR=%s XAUTHORITY=%s\n",
			user, os.Getenv("DISPLAY"), os.Getenv("WAYLAND_DISPLAY"),
			os.Getenv("XDG_RUNTIME_DIR"), os.Getenv("XAUTHORITY"))
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

// launchWebView opens a WebView window pointing to the given URL.
// This blocks until the WebView is closed.
func launchWebView(url string, fullscreen bool) error {
	ensureDisplayEnv()

	display := os.Getenv("DISPLAY")
	wayland := os.Getenv("WAYLAND_DISPLAY")
	if display == "" && wayland == "" {
		return errors.New("kiosk requires a display: set DISPLAY or WAYLAND_DISPLAY environment variable")
	}

	// Log what we detected for troubleshooting
	fmt.Fprintf(os.Stderr, "[kiosk] display env: DISPLAY=%s XAUTHORITY=%s WAYLAND_DISPLAY=%s XDG_RUNTIME_DIR=%s\n",
		display, os.Getenv("XAUTHORITY"), wayland, os.Getenv("XDG_RUNTIME_DIR"))

	title := C.CString("Kiosk")
	defer C.free(unsafe.Pointer(title))

	urlC := C.CString(url)
	defer C.free(unsafe.Pointer(urlC))

	fs := 0
	if fullscreen {
		fs = 1
	}

	if result := C.init_webview(title, 1920, 1080, C.int(fs)); result != 0 {
		switch C.get_init_error() {
		case 1:
			return fmt.Errorf("failed to initialize GTK (DISPLAY=%s, XAUTHORITY=%s): ensure the graphical session is active and the agent can access it",
				display, os.Getenv("XAUTHORITY"))
		case 2:
			return errors.New("failed to create GTK window")
		case 3:
			return errors.New("failed to create WebKit view: ensure libwebkit2gtk-4.0-37 is installed")
		default:
			return errors.New("unknown kiosk initialization error")
		}
	}

	registerNavigate(func(u string) {
		cs := C.CString(u)
		defer C.free(unsafe.Pointer(cs))
		C.navigate_async(cs)
	})
	defer registerNavigate(nil)

	C.navigate(urlC)
	C.run_webview()

	return nil
}
