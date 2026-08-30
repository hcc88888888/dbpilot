//go:build linux

package main

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

func setProcessName(name string) error {
	pointer, err := unix.BytePtrFromString(name)
	if err != nil {
		return err
	}
	err = unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(pointer)), 0, 0, 0)
	runtime.KeepAlive(pointer)
	return err
}
