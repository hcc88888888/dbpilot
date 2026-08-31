//go:build linux

package pluginsupervisor

import (
	"errors"
	"os"
	"path/filepath"
)

func prepareRuntimeSocket(runtimeDirectory string) error {
	path := filepath.Join(runtimeDirectory, "plugin.sock")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return ErrProcessStart
	}
	if err := os.Remove(path); err != nil {
		return ErrProcessStart
	}
	return syncDirectoryPath(runtimeDirectory)
}
