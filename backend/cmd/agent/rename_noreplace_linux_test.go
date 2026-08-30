//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRenameEnrollmentGenerationNoReplacePreservesRacedEmptyDestination(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	require.NoError(t, os.Mkdir(source, 0o700))
	require.NoError(t, os.Mkdir(destination, 0o700))

	err := renameEnrollmentGenerationNoReplace(source, destination)

	require.Error(t, err)
	require.DirExists(t, source)
	require.DirExists(t, destination)
}
