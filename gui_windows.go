//go:build windows

package main

import (
	"os"
	"os/exec"

	webview "github.com/webview/webview_go"
)

// openWindow launches the panel as a native window in a separate process, so
// the webview event loop never fights the engine for the main thread.
func openWindow(url string) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	exec.Command(exe, "--window="+url).Start()
}

// runWindow shows the native webview window (runs in the child --window process).
func runWindow(url string) {
	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("Lampa Downloader")
	w.SetSize(600, 780, webview.HintNone)
	w.Navigate(url)
	w.Run()
}
