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
	"unsafe"
)

// webviewAvailable indicates whether WebView support is compiled in.
const webviewAvailable = true

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
