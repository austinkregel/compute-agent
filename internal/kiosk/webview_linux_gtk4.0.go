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
	"unsafe"
)

// webviewAvailable indicates whether WebView support is compiled in.
const webviewAvailable = true

// ensureDisplayEnv auto-detects and sets X11/Wayland environment variables
// when the agent runs as a system service (supervisord, systemd, etc.).
// A graphical session owned by another user requires DISPLAY + XAUTHORITY
// (X11) or WAYLAND_DISPLAY + XDG_RUNTIME_DIR (Wayland) to be set.
func ensureDisplayEnv() {
	// X11: fully configured
	if os.Getenv("DISPLAY") != "" && os.Getenv("XAUTHORITY") != "" {
		return
	}
	// Wayland: fully configured
	if os.Getenv("WAYLAND_DISPLAY") != "" && os.Getenv("XDG_RUNTIME_DIR") != "" {
		return
	}

	// Use loginctl to discover active graphical sessions.
	out, err := exec.Command("loginctl", "list-sessions", "--no-legend").Output()
	if err != nil {
		// loginctl not available; try fallback scan
		ensureDisplayEnvFallback()
		return
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		sessionID := fields[0]

		propOut, err := exec.Command("loginctl", "show-session", sessionID,
			"-p", "Type", "-p", "Display", "-p", "User", "-p", "Name").Output()
		if err != nil {
			continue
		}

		var sessType, display, uid, user string
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
			}
		}

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
				for _, candidate := range xauthorityCandidates(user, uid) {
					if _, err := os.Stat(candidate); err == nil {
						os.Setenv("XAUTHORITY", candidate)
						break
					}
				}
			}
			return
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
			for _, candidate := range xauthorityCandidates(user, uid) {
				if _, err := os.Stat(candidate); err == nil {
					os.Setenv("XAUTHORITY", candidate)
					break
				}
			}
		}
		return
	}

	// No graphical session found via loginctl; try fallback
	ensureDisplayEnvFallback()
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

// ensureDisplayEnvFallback scans common locations when loginctl is unavailable.
func ensureDisplayEnvFallback() {
	if os.Getenv("DISPLAY") == "" {
		// Check for X sockets in /tmp/.X11-unix
		entries, err := os.ReadDir("/tmp/.X11-unix")
		if err == nil {
			for _, e := range entries {
				name := e.Name()
				if strings.HasPrefix(name, "X") {
					os.Setenv("DISPLAY", ":"+name[1:])
					break
				}
			}
		}
	}

	if os.Getenv("DISPLAY") != "" && os.Getenv("XAUTHORITY") == "" {
		// Scan /home/*/.Xauthority
		homes, err := os.ReadDir("/home")
		if err == nil {
			for _, h := range homes {
				if !h.IsDir() {
					continue
				}
				candidate := filepath.Join("/home", h.Name(), ".Xauthority")
				if _, err := os.Stat(candidate); err == nil {
					os.Setenv("XAUTHORITY", candidate)
					return
				}
			}
		}
	}
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

	C.navigate(urlC)
	C.run_webview()

	return nil
}
