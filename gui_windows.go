//go:build windows

package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"

	"fyne.io/systray"
	webview "github.com/webview/webview_go"
)

// openWindow launches the panel as a native window in a separate process, so
// the webview event loop never fights the engine/tray for the main thread.
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

// runAgentGUI runs the tray in the main process (blocks). The panel opens in a
// child process; closing it leaves the agent running in the tray.
func runAgentGUI(a *Agent, uiURL string) {
	onReady := func() {
		systray.SetIcon(trayIcon)
		systray.SetTitle("")
		systray.SetTooltip("Lampa Downloader")
		mOpen := systray.AddMenuItem("Открыть панель", "")
		mDir := systray.AddMenuItem("Папка загрузок", "")
		systray.AddSeparator()
		mQuit := systray.AddMenuItem("Выход", "")

		openWindow(uiURL) // show panel on first launch

		go func() {
			for {
				select {
				case <-mOpen.ClickedCh:
					openWindow(uiURL)
				case <-mDir.ClickedCh:
					openPath(a.cfg.DownloadDir)
				case <-mQuit.ClickedCh:
					systray.Quit()
				}
			}
		}()
	}
	systray.Run(onReady, func() { os.Exit(0) })
}

// pickDir shows the native Windows folder chooser; returns "" if cancelled.
func pickDir() string {
	ps := `Add-Type -AssemblyName System.Windows.Forms;` +
		`$f=New-Object System.Windows.Forms.FolderBrowserDialog;` +
		`if($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){[Console]::Out.Write($f.SelectedPath)}`
	cmd := exec.Command("powershell", "-NoProfile", "-STA", "-Command", ps)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
