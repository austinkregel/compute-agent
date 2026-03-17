//go:build cgo && darwin

package kiosk

/*
#cgo darwin CFLAGS: -x objective-c
#cgo darwin LDFLAGS: -framework Cocoa -framework WebKit

#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

static NSWindow *window = nil;
static WKWebView *webView = nil;

void initWebView(const char *title, int width, int height, int fullscreen) {
    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

        NSRect frame = NSMakeRect(0, 0, width, height);
        NSWindowStyleMask style = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                   NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable;

        window = [[NSWindow alloc] initWithContentRect:frame
                                             styleMask:style
                                               backing:NSBackingStoreBuffered
                                                 defer:NO];

        [window setTitle:[NSString stringWithUTF8String:title]];
        [window center];

        WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
        webView = [[WKWebView alloc] initWithFrame:frame configuration:config];
        [window setContentView:webView];

        if (fullscreen) {
            [window toggleFullScreen:nil];
        }
    }
}

void navigateTo(const char *url) {
    @autoreleasepool {
        NSString *urlStr = [NSString stringWithUTF8String:url];
        NSURL *nsurl = [NSURL URLWithString:urlStr];
        NSURLRequest *request = [NSURLRequest requestWithURL:nsurl];
        [webView loadRequest:request];
    }
}

// Thread-safe: schedule navigation on the main thread from any goroutine.
void navigateAsync(const char *url) {
    char *urlCopy = strdup(url);
    dispatch_async(dispatch_get_main_queue(), ^{
        @autoreleasepool {
            NSString *urlStr = [NSString stringWithUTF8String:urlCopy];
            NSURL *nsurl = [NSURL URLWithString:urlStr];
            NSURLRequest *request = [NSURLRequest requestWithURL:nsurl];
            [webView loadRequest:request];
        }
        free(urlCopy);
    });
}

void runWebView() {
    @autoreleasepool {
        [window makeKeyAndOrderFront:nil];
        [NSApp activateIgnoringOtherApps:YES];
        [NSApp run];
    }
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

	C.initWebView(title, 1920, 1080, C.int(fs))

	registerNavigate(func(u string) {
		cs := C.CString(u)
		defer C.free(unsafe.Pointer(cs))
		C.navigateAsync(cs)
	})
	defer registerNavigate(nil)

	C.navigateTo(urlC)
	C.runWebView()

	return nil
}
