//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows/registry"
)

// enableAutostart registers the agent to launch at Windows logon (per-user).
func enableAutostart() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	k.SetStringValue("LampaDownloader", `"`+exe+`"`)
}
