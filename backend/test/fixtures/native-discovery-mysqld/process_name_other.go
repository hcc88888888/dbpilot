//go:build !linux

package main

import "errors"

func setProcessName(string) error { return errors.New("process naming is supported only on Linux") }
