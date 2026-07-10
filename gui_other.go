//go:build !windows

package main

import (
	"os/exec"
	"runtime"
)

// openWindow opens the panel in the default browser on non-Windows platforms.
func openWindow(url string) {
	switch runtime.GOOS {
	case "darwin":
		exec.Command("open", url).Start()
	default:
		exec.Command("xdg-open", url).Start()
	}
}

// runWindow has no native webview off Windows yet; fall back to a browser.
func runWindow(url string) { openWindow(url) }

// runAgentGUI (non-Windows): open the panel once and keep running headless.
func runAgentGUI(a *Agent, uiURL string) {
	openWindow(uiURL)
	select {}
}

// pickDir: no native folder dialog off Windows yet.
func pickDir() string { return "" }

// listDrives: non-Windows has a single root.
func listDrives() []string { return []string{"/"} }
