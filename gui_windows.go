//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

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
	setWindowIcon(uintptr(w.Window())) // title-bar + taskbar icon
	w.Run()
}

var (
	user32          = syscall.NewLazyDLL("user32.dll")
	procSendMessage = user32.NewProc("SendMessageW")
	procLoadImage   = user32.NewProc("LoadImageW")
)

const (
	wmSetIcon     = 0x0080
	iconSmall     = 0
	iconBig       = 1
	imageIcon     = 1
	lrLoadFile    = 0x0010
	lrDefaultSize = 0x0040
)

// setWindowIcon loads the embedded app icon and assigns it to the window.
func setWindowIcon(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	tmp := filepath.Join(os.TempDir(), "lampa-agent.ico")
	if os.WriteFile(tmp, appIcon, 0644) != nil {
		return
	}
	p, err := syscall.UTF16PtrFromString(tmp)
	if err != nil {
		return
	}
	hicon, _, _ := procLoadImage.Call(0, uintptr(unsafe.Pointer(p)), imageIcon, 0, 0, lrLoadFile|lrDefaultSize)
	if hicon != 0 {
		procSendMessage.Call(hwnd, wmSetIcon, iconBig, hicon)
		procSendMessage.Call(hwnd, wmSetIcon, iconSmall, hicon)
	}
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

// listDrives returns available Windows drive roots (C:\, D:\, ...).
func listDrives() []string {
	var out []string
	for c := 'A'; c <= 'Z'; c++ {
		root := string(c) + ":\\"
		if _, err := os.Stat(root); err == nil {
			out = append(out, root)
		}
	}
	return out
}

// pickDir is unused now (in-panel browser replaces the native dialog) but kept
// as a fallback so the /api/pickdir route stays valid.
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
