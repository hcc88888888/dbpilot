//go:build linux

package spool

import (
	"os"
	"syscall"
)

func validatePrivateDirectory(info os.FileInfo) error {
	if info.Mode().Perm() != 0o700 {
		return ErrInvalidRoot
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return ErrInvalidRoot
	}
	return nil
}
