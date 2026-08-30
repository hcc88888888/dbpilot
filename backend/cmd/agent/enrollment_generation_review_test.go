package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/enrollment"
	"github.com/stretchr/testify/require"
)

var errEnrollmentCrash = errors.New("simulated enrollment process crash")

func TestPrepareEnrollmentGenerationRetriesParentSyncBeforeRPCWithSameCSR(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "credentials")
	token := bytes.Repeat([]byte{0x51}, enrollment.EnrollmentTokenBytes)
	filesystem := systemEnrollmentFilesystem()
	realSync := filesystem.syncDirectory
	failed := false
	filesystem.syncDirectory = func(path string) error {
		if !failed && filepath.Clean(path) == filepath.Clean(root) {
			failed = true
			return errEnrollmentCrash
		}
		return realSync(path)
	}

	_, err := prepareEnrollmentGenerationWithFilesystem(output, "agent-1", token, validCLIHostObservation(), rand.Reader, filesystem)
	require.ErrorIs(t, err, errEnrollmentCrash)
	stagedCSR, err := os.ReadFile(filepath.Join(enrollmentStageDirectory(output), enrollmentCSRFilename))
	require.NoError(t, err)

	resumed, err := prepareEnrollmentGeneration(output, "agent-1", token, validCLIHostObservation(), failingEnrollmentReader{})
	require.NoError(t, err)
	require.Equal(t, stagedCSR, resumed.request.GetCertificateSigningRequestPem())
}

func TestPrepareEnrollmentGenerationFallsBackFromIncompleteCommitManifest(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "credentials")
	token := bytes.Repeat([]byte{0x52}, enrollment.EnrollmentTokenBytes)
	first, err := prepareEnrollmentGeneration(output, "agent-1", token, validCLIHostObservation(), rand.Reader)
	require.NoError(t, err)
	firstCSR := append([]byte(nil), first.request.GetCertificateSigningRequestPem()...)
	require.NoError(t, os.WriteFile(filepath.Join(first.stageDirectory, enrollmentCommitFilename), []byte(`{"state":"comp`), 0o600))

	resumed, err := prepareEnrollmentGeneration(output, "agent-1", token, validCLIHostObservation(), failingEnrollmentReader{})
	require.NoError(t, err)
	require.Equal(t, firstCSR, resumed.request.GetCertificateSigningRequestPem())
	_, err = os.Lstat(filepath.Join(first.stageDirectory, enrollmentCommitFilename))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestAtomicEnrollmentFileFaultsNeverExposePartialCanonicalContent(t *testing.T) {
	for _, operation := range []string{"write", "sync", "close", "rename", "directory-sync"} {
		t.Run(operation, func(t *testing.T) {
			directory := t.TempDir()
			filesystem := systemEnrollmentFilesystem()
			realCreate := filesystem.createTemp
			realRename := filesystem.renameCanonical
			realDirectorySync := filesystem.syncDirectory
			if operation == "write" || operation == "sync" || operation == "close" {
				filesystem.createTemp = func(directory, pattern string) (enrollmentWritableFile, error) {
					file, err := realCreate(directory, pattern)
					return &faultEnrollmentFile{enrollmentWritableFile: file, operation: operation}, err
				}
			}
			if operation == "rename" {
				filesystem.renameCanonical = func(oldPath, newPath string) error {
					if err := realRename(oldPath, newPath); err != nil {
						return err
					}
					return errEnrollmentCrash
				}
			}
			if operation == "directory-sync" {
				filesystem.syncDirectory = func(path string) error {
					if filepath.Clean(path) == filepath.Clean(directory) {
						return errEnrollmentCrash
					}
					return realDirectorySync(path)
				}
			}
			want := []byte("complete credential material")

			err := writeEnrollmentFileAtomic(directory, agentKeyFilename, want, filesystem)
			require.Error(t, err)
			canonical := filepath.Join(directory, agentKeyFilename)
			if got, readErr := os.ReadFile(canonical); readErr == nil {
				require.Equal(t, want, got, "a canonical name may expose only complete content")
			} else {
				require.ErrorIs(t, readErr, os.ErrNotExist)
			}

			require.NoError(t, writeEnrollmentFileAtomicResumable(directory, agentKeyFilename, want, systemEnrollmentFilesystem()))
			got, err := os.ReadFile(canonical)
			require.NoError(t, err)
			require.Equal(t, want, got)
			for _, entry := range mustReadDirectory(t, directory) {
				require.False(t, strings.HasPrefix(entry.Name(), enrollmentTemporaryPrefix))
			}
		})
	}
}

func TestEnrollmentGenerationResumesAfterCertificateCanonicalRenameCrash(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "credentials")
	token := bytes.Repeat([]byte{0x53}, enrollment.EnrollmentTokenBytes)
	generation, err := prepareEnrollmentGeneration(output, "agent-1", token, validCLIHostObservation(), rand.Reader)
	require.NoError(t, err)
	response, serverCA := testEnrollmentResponse(t, generation.request)
	filesystem := systemEnrollmentFilesystem()
	realRename := filesystem.renameCanonical
	failed := false
	filesystem.renameCanonical = func(oldPath, newPath string) error {
		err := realRename(oldPath, newPath)
		if err == nil && !failed && filepath.Base(newPath) == agentCertificateFilename {
			failed = true
			return errEnrollmentCrash
		}
		return err
	}
	generation.filesystem = filesystem

	err = generation.complete(response, serverCA)
	require.ErrorIs(t, err, errEnrollmentCrash)
	require.FileExists(t, filepath.Join(generation.stageDirectory, agentCertificateFilename))

	resumed, err := prepareEnrollmentGeneration(output, "agent-1", token, validCLIHostObservation(), failingEnrollmentReader{})
	require.NoError(t, err)
	require.False(t, resumed.readyToPublish())
	require.NoError(t, resumed.complete(response, serverCA))
	require.NoError(t, resumed.publish(serverCA))
	require.DirExists(t, output)
}

func TestEnrollmentGenerationIgnoresKnownTemporaryCrashResidue(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "credentials")
	token := bytes.Repeat([]byte{0x54}, enrollment.EnrollmentTokenBytes)
	generation, err := prepareEnrollmentGeneration(output, "agent-1", token, validCLIHostObservation(), rand.Reader)
	require.NoError(t, err)
	residue := filepath.Join(generation.stageDirectory, enrollmentTemporaryPrefix+agentCertificateFilename+"-dead")
	require.NoError(t, os.WriteFile(residue, []byte("partial certificate"), 0o600))
	response, serverCA := testEnrollmentResponse(t, generation.request)

	require.NoError(t, generation.complete(response, serverCA))
	require.NoError(t, generation.publish(serverCA))
	require.NoFileExists(t, residue)
	require.DirExists(t, output)
}

func TestEnrollmentGenerationAtomicNoReplaceRejectsDestinationRace(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "credentials")
	token := bytes.Repeat([]byte{0x55}, enrollment.EnrollmentTokenBytes)
	generation, err := prepareEnrollmentGeneration(output, "agent-1", token, validCLIHostObservation(), rand.Reader)
	require.NoError(t, err)
	response, serverCA := testEnrollmentResponse(t, generation.request)
	require.NoError(t, generation.complete(response, serverCA))
	filesystem := systemEnrollmentFilesystem()
	realRename := filesystem.renameNoReplace
	filesystem.renameNoReplace = func(oldPath, newPath string) error {
		require.NoError(t, os.Mkdir(newPath, 0o700))
		return realRename(oldPath, newPath)
	}
	generation.filesystem = filesystem

	err = generation.publish(serverCA)
	require.Error(t, err)
	require.DirExists(t, output)
	require.Empty(t, mustReadDirectory(t, output))
	require.DirExists(t, generation.stageDirectory)
}

func TestEnrollmentGenerationResumesAfterFinalManifestBeforeTransitionCleanup(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "credentials")
	token := bytes.Repeat([]byte{0x57}, enrollment.EnrollmentTokenBytes)
	generation, err := prepareEnrollmentGeneration(output, "agent-1", token, validCLIHostObservation(), rand.Reader)
	require.NoError(t, err)
	response, serverCA := testEnrollmentResponse(t, generation.request)
	require.NoError(t, generation.complete(response, serverCA))
	filesystem := systemEnrollmentFilesystem()
	realRemove := filesystem.remove
	failed := false
	filesystem.remove = func(path string) error {
		if !failed && filepath.Base(path) == enrollmentCSRFilename {
			failed = true
			return errEnrollmentCrash
		}
		return realRemove(path)
	}
	generation.filesystem = filesystem

	err = generation.publish(serverCA)
	require.ErrorIs(t, err, errEnrollmentCrash)
	manifest, err := readEnrollmentGenerationManifest(filepath.Join(generation.stageDirectory, enrollmentCommitFilename))
	require.NoError(t, err)
	require.Equal(t, enrollmentGenerationFinalized, manifest.State)

	resumed, err := prepareEnrollmentGeneration(output, "agent-1", token, validCLIHostObservation(), failingEnrollmentReader{})
	require.NoError(t, err)
	require.NoError(t, resumed.publish(serverCA))
	require.DirExists(t, output)
	require.Len(t, mustReadDirectory(t, output), 4)
}

func TestCompletedEnrollmentGenerationRejectsSemanticSubstitution(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, generation *enrollmentGeneration, manifest *enrollmentGenerationManifest)
	}{
		{name: "empty host", mutate: func(_ *testing.T, _ *enrollmentGeneration, manifest *enrollmentGenerationManifest) {
			manifest.HostID = ""
		}},
		{name: "zero revision", mutate: func(_ *testing.T, _ *enrollmentGeneration, manifest *enrollmentGenerationManifest) {
			manifest.EnrollmentRevision = 0
		}},
		{name: "certificate from another key", mutate: func(t *testing.T, generation *enrollmentGeneration, manifest *enrollmentGenerationManifest) {
			otherRoot := t.TempDir()
			other, err := prepareEnrollmentGeneration(filepath.Join(otherRoot, "credentials"), "agent-1", bytes.Repeat([]byte{0x66}, enrollment.EnrollmentTokenBytes), validCLIHostObservation(), rand.Reader)
			require.NoError(t, err)
			otherResponse, _ := testEnrollmentResponse(t, other.request)
			certificate := append(append([]byte(nil), otherResponse.GetCertificatePem()...), otherResponse.GetCertificateChainPem()...)
			require.NoError(t, os.WriteFile(filepath.Join(generation.stageDirectory, agentCertificateFilename), certificate, 0o600))
			manifest.CertificateSHA256 = enrollmentDigest(certificate)
			manifest.ExpiresAtUTC = otherResponse.GetExpiresAt().AsTime().UTC().Format(time.RFC3339Nano)
		}},
		{name: "CSR from another key", mutate: func(t *testing.T, generation *enrollmentGeneration, manifest *enrollmentGenerationManifest) {
			otherRoot := t.TempDir()
			other, err := prepareEnrollmentGeneration(filepath.Join(otherRoot, "credentials"), "agent-1", bytes.Repeat([]byte{0x67}, enrollment.EnrollmentTokenBytes), validCLIHostObservation(), rand.Reader)
			require.NoError(t, err)
			csr := append([]byte(nil), other.request.GetCertificateSigningRequestPem()...)
			require.NoError(t, os.WriteFile(filepath.Join(generation.stageDirectory, enrollmentCSRFilename), csr, 0o600))
			manifest.CSRPublicSHA256 = enrollmentDigest(csr)
		}},
		{name: "untrusted CA", mutate: func(t *testing.T, generation *enrollmentGeneration, manifest *enrollmentGenerationManifest) {
			other, _ := testEnrollmentResponse(t, generation.request)
			otherCA := append([]byte(nil), other.GetCertificateChainPem()...)
			require.NoError(t, os.WriteFile(filepath.Join(generation.stageDirectory, agentCAFilename), otherCA, 0o600))
			manifest.CASHA256 = enrollmentDigest(otherCA)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			output := filepath.Join(root, "credentials")
			token := bytes.Repeat([]byte{0x56}, enrollment.EnrollmentTokenBytes)
			generation, err := prepareEnrollmentGeneration(output, "agent-1", token, validCLIHostObservation(), rand.Reader)
			require.NoError(t, err)
			response, serverCA := testEnrollmentResponse(t, generation.request)
			require.NoError(t, generation.complete(response, serverCA))
			manifestPath := filepath.Join(generation.stageDirectory, enrollmentCompleteFilename)
			manifest, err := readEnrollmentGenerationManifest(manifestPath)
			require.NoError(t, err)
			test.mutate(t, generation, &manifest)
			rewriteEnrollmentManifest(t, manifestPath, manifest)

			resumed, err := prepareEnrollmentGeneration(output, "agent-1", token, validCLIHostObservation(), failingEnrollmentReader{})
			if err == nil {
				err = resumed.publish(serverCA)
			}
			require.Error(t, err)
			require.NoDirExists(t, output)
		})
	}
}

func rewriteEnrollmentManifest(t *testing.T, path string, manifest enrollmentGenerationManifest) {
	t.Helper()
	contents, err := json.Marshal(manifest)
	require.NoError(t, err)
	contents = append(contents, '\n')
	require.NoError(t, os.WriteFile(path, contents, 0o600))
}

type faultEnrollmentFile struct {
	enrollmentWritableFile
	operation string
}

func (file *faultEnrollmentFile) Write(value []byte) (int, error) {
	if file.operation == "write" {
		partial := len(value) / 2
		written, _ := file.enrollmentWritableFile.Write(value[:partial])
		return written, errEnrollmentCrash
	}
	return file.enrollmentWritableFile.Write(value)
}

func (file *faultEnrollmentFile) Sync() error {
	if file.operation == "sync" {
		return errEnrollmentCrash
	}
	return file.enrollmentWritableFile.Sync()
}

func (file *faultEnrollmentFile) Close() error {
	err := file.enrollmentWritableFile.Close()
	if err == nil && file.operation == "close" {
		return errEnrollmentCrash
	}
	return err
}
