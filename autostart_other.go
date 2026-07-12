//go:build !windows

package main

// setAutostart is a no-op off Windows for now (NAS/servers run headless).
func setAutostart(on bool) error { return nil }

// autostartEnabled always reports false off Windows.
func autostartEnabled() bool { return false }
