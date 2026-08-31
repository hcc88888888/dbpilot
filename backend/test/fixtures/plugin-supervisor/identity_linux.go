//go:build linux

package main

import "os"

func currentUID() int { return os.Geteuid() }
func currentGID() int { return os.Getegid() }
