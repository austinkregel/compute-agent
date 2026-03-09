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
	"os"
	"unsafe"
)

// webviewAvailable indicates whether WebView support is compiled in.
const webviewAvailable = true

// launchWebView opens a WebView window pointing to the given URL.
// This blocks until the WebView is closed.
func launchWebView(url string, fullscreen bool) error {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return errors.New("kiosk requires a display: set DISPLAY or WAYLAND_DISPLAY environment variable")
	}

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
			return errors.New("failed to initialize GTK: ensure DISPLAY is set and X11/Wayland is running")
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
