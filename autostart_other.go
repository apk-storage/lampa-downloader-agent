//go:build !windows

package main

// enableAutostart is a no-op on non-Windows for now (NAS/servers run headless).
func enableAutostart() {}
