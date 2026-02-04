//go:build cgo && linux

package kiosk

/*
#cgo linux pkg-config: gtk+-3.0 webkit2gtk-4.1
#cgo linux CXXFLAGS: -DWEBVIEW_GTK -std=c++11
#cgo linux LDFLAGS: -ldl

#include <gtk/gtk.h>
#include <webkit2/webkit2.h>
#include <stdlib.h>

static GtkWidget *window = NULL;
static GtkWidget *webview = NULL;

static void init_webview(const char *title, int width, int height, int fullscreen) {
    gtk_init(NULL, NULL);
    
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), title);
    gtk_window_set_default_size(GTK_WINDOW(window), width, height);
    
    if (fullscreen) {
        gtk_window_fullscreen(GTK_WINDOW(window));
    }
    
    webview = webkit_web_view_new();
    gtk_container_add(GTK_CONTAINER(window), webview);
    
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
}

static void navigate(const char *url) {
    webkit_web_view_load_uri(WEBKIT_WEB_VIEW(webview), url);
}

static void run_webview() {
    gtk_widget_show_all(window);
    gtk_main();
}
*/
import "C"
import "unsafe"

// webviewAvailable indicates whether WebView support is compiled in.
const webviewAvailable = true

// launchWebView opens a WebView window pointing to the given URL.
// This blocks until the WebView is closed.
func launchWebView(url string, fullscreen bool) error {
	title := C.CString("Kiosk")
	defer C.free(unsafe.Pointer(title))
	
	urlC := C.CString(url)
	defer C.free(unsafe.Pointer(urlC))
	
	fs := 0
	if fullscreen {
		fs = 1
	}
	
	C.init_webview(title, 1920, 1080, C.int(fs))
	C.navigate(urlC)
	C.run_webview()
	
	return nil
}
