//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// freeSpace reports bytes available to the user on the volume holding path.
func freeSpace(path string) (int64, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var freeAvail, total, totalFree uint64
	k := syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")
	r, _, e := k.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&freeAvail)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r == 0 {
		return 0, e
	}
	return int64(freeAvail), nil
}
