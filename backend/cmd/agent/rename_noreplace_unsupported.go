//go:build !linux && !windows

package main

import "errors"

func renameEnrollmentGenerationNoReplace(_, _ string) error {
	return errors.New("atomic no-replace enrollment publication is unsupported on this platform")
}
