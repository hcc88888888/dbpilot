//go:build !linux

package spool

import "os"

func validatePrivateDirectory(info os.FileInfo) error { return nil }
