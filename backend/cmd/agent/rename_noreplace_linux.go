//go:build linux

package main

import "golang.org/x/sys/unix"

func renameEnrollmentGenerationNoReplace(oldPath, newPath string) error {
	return unix.Renameat2(unix.AT_FDCWD, oldPath, unix.AT_FDCWD, newPath, unix.RENAME_NOREPLACE)
}
