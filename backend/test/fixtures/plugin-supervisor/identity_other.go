//go:build !linux

package main

func currentUID() int { return -1 }
func currentGID() int { return -1 }
