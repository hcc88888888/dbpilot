package pluginsupervisor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"testing"
	"time"

	"dbpilot.local/platform/internal/agent/pluginstate"
	"dbpilot.local/platform/internal/plugincatalog"
	"github.com/stretchr/testify/require"
)

func TestInstallerConsumesSharedSignatureCorpusAndCreatesPrivateInactiveSlot(t *testing.T) {
	archive, publicKey, manifestDigest := sharedCorpusArchive(t)
	root := t.TempDir()
	installer := newTestInstaller(t, root, publicKey)
	packageDigest := sha256.Sum256(archive)

	installed, err := installer.InstallInactive(context.Background(), InstallRequest{
		DatabaseFamily: "mysql", PluginID: "mysql", Version: "1.0.0",
		ArtifactSHA256: packageDigest[:], ManifestDigest: manifestDigest,
		Archive: bytes.NewReader(archive), ArchiveSize: int64(len(archive)),
	}, pluginstate.SlotB)
	require.NoError(t, err)
	require.Equal(t, pluginstate.SlotB, installed.Slot)
	require.FileExists(t, installed.ExecutablePath)
	require.FileExists(t, installed.ManifestPath)
	executableBytes := requireReadFile(t, installed.ExecutablePath)
	executableDigest := sha256.Sum256(executableBytes)
	require.Equal(t, hex.EncodeToString(executableDigest[:]), installed.ExecutableSHA256)
	require.NoFileExists(t, filepath.Join(root, "mysql", activeMarkerName))

	if runtime.GOOS != "windows" {
		executable, statErr := os.Stat(installed.ExecutablePath)
		require.NoError(t, statErr)
		require.Equal(t, os.FileMode(0o500), executable.Mode().Perm())
		manifest, statErr := os.Stat(installed.ManifestPath)
		require.NoError(t, statErr)
		require.Equal(t, os.FileMode(0o400), manifest.Mode().Perm())
	}

	require.NoError(t, installer.Activate(context.Background(), SlotIdentity{DatabaseFamily: "mysql", PluginID: "mysql", Version: "1.0.0", ArtifactSHA256: hex.EncodeToString(packageDigest[:]), ManifestDigest: hex.EncodeToString(manifestDigest)}, pluginstate.SlotB))
	active, err := installer.ActiveSlot("mysql")
	require.NoError(t, err)
	require.Equal(t, pluginstate.SlotB, active)
}

func TestInstallerRejectsDigestSignaturePlatformAndActiveOverwrite(t *testing.T) {
	archive, publicKey, manifestDigest := sharedCorpusArchive(t)
	packageDigest := sha256.Sum256(archive)
	tests := map[string]func(*InstallRequest, *Installer){
		"package digest":  func(request *InstallRequest, _ *Installer) { request.ArtifactSHA256[0] ^= 0xff },
		"manifest digest": func(request *InstallRequest, _ *Installer) { request.ManifestDigest[0] ^= 0xff },
		"signature": func(request *InstallRequest, _ *Installer) {
			corrupt := append([]byte(nil), archive...)
			corrupt[len(corrupt)/2] ^= 0xff
			request.Archive, request.ArchiveSize = bytes.NewReader(corrupt), int64(len(corrupt))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			installer := newTestInstaller(t, t.TempDir(), publicKey)
			request := InstallRequest{DatabaseFamily: "mysql", PluginID: "mysql", Version: "1.0.0", ArtifactSHA256: append([]byte(nil), packageDigest[:]...), ManifestDigest: append([]byte(nil), manifestDigest...), Archive: bytes.NewReader(archive), ArchiveSize: int64(len(archive))}
			mutate(&request, installer)
			_, err := installer.InstallInactive(context.Background(), request, pluginstate.SlotA)
			require.Error(t, err)
		})
	}

	installer := newTestInstaller(t, t.TempDir(), publicKey)
	request := InstallRequest{DatabaseFamily: "mysql", PluginID: "mysql", Version: "1.0.0", ArtifactSHA256: packageDigest[:], ManifestDigest: manifestDigest, Archive: bytes.NewReader(archive), ArchiveSize: int64(len(archive))}
	_, err := installer.InstallInactive(context.Background(), request, pluginstate.SlotA)
	require.NoError(t, err)
	require.NoError(t, installer.Activate(context.Background(), identityFromRequest(ReconcileRequest{DatabaseFamily: "mysql", PluginID: "mysql", DesiredVersion: "1.0.0", ArtifactSHA256: packageDigest[:], ManifestDigest: manifestDigest}), pluginstate.SlotA))
	request.Archive = bytes.NewReader(archive)
	_, err = installer.InstallInactive(context.Background(), request, pluginstate.SlotA)
	require.ErrorIs(t, err, ErrInstallFailed)
}

func TestInstallerRejectsTraversalLinksCaseCollisionsAndUnsafeModes(t *testing.T) {
	_, publicKey, _ := sharedCorpusArchive(t)
	for name, header := range map[string]tar.Header{
		"traversal": {Name: "plugin-package/../escape", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg},
		"symlink":   {Name: "plugin-package/link", Linkname: "/tmp", Typeflag: tar.TypeSymlink},
		"hardlink":  {Name: "plugin-package/hard", Linkname: "plugin-package/manifest.json", Typeflag: tar.TypeLink},
		"device":    {Name: "plugin-package/device", Typeflag: tar.TypeChar},
	} {
		t.Run(name, func(t *testing.T) {
			archive := malformedArchive(t, []tar.Header{header})
			digest := sha256.Sum256(archive)
			installer := newTestInstaller(t, t.TempDir(), publicKey)
			_, err := installer.InstallInactive(context.Background(), InstallRequest{DatabaseFamily: "mysql", PluginID: "mysql", Version: "1.0.0", ArtifactSHA256: digest[:], ManifestDigest: bytesOf(1, sha256.Size), Archive: bytes.NewReader(archive), ArchiveSize: int64(len(archive))}, pluginstate.SlotA)
			require.Error(t, err)
		})
	}

	archive := malformedArchive(t, []tar.Header{
		{Name: "plugin-package/manifest.json", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg},
		{Name: "plugin-package/Manifest.json", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg},
	})
	digest := sha256.Sum256(archive)
	installer := newTestInstaller(t, t.TempDir(), publicKey)
	_, err := installer.InstallInactive(context.Background(), InstallRequest{DatabaseFamily: "mysql", PluginID: "mysql", Version: "1.0.0", ArtifactSHA256: digest[:], ManifestDigest: bytesOf(1, sha256.Size), Archive: bytes.NewReader(archive), ArchiveSize: int64(len(archive))}, pluginstate.SlotA)
	require.Error(t, err)
}

func TestInstallerRecoveryRemovesIncompleteStagingWithoutTouchingCompletedSlot(t *testing.T) {
	root := t.TempDir()
	_, publicKey, _ := sharedCorpusArchive(t)
	installer := newTestInstaller(t, root, publicKey)
	familyRoot := filepath.Join(root, "mysql")
	require.NoError(t, os.MkdirAll(filepath.Join(familyRoot, slotsDirectoryName, "A"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(familyRoot, slotsDirectoryName, "A", completionMarkerName), []byte(`{"version":"1.0.0"}`), 0o400))
	staging := filepath.Join(familyRoot, ".install-incomplete")
	require.NoError(t, os.MkdirAll(staging, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(staging, "partial"), []byte("partial"), 0o600))

	require.NoError(t, installer.Recover(context.Background(), "mysql"))
	require.NoDirExists(t, staging)
	require.FileExists(t, filepath.Join(familyRoot, slotsDirectoryName, "A", completionMarkerName))
}

func TestInstallerRemoveInactiveIsIdempotentBeforeFamilySlotsExist(t *testing.T) {
	_, publicKey, _ := sharedCorpusArchive(t)
	installer := newTestInstaller(t, t.TempDir(), publicKey)
	require.NoError(t, installer.RemoveInactive(context.Background(), "mysql", pluginstate.SlotA))
}

func TestInstallerRejectsSignedCaseCollisionAndInstalledHardlinkMutation(t *testing.T) {
	archive, publicKey, manifestDigest := signedCaseCollisionArchive(t)
	digest := sha256.Sum256(archive)
	installer := newTestInstaller(t, t.TempDir(), publicKey)
	_, err := installer.InstallInactive(context.Background(), InstallRequest{DatabaseFamily: "mysql", PluginID: "mysql", Version: "1.0.0", ArtifactSHA256: digest[:], ManifestDigest: manifestDigest, Archive: bytes.NewReader(archive), ArchiveSize: int64(len(archive))}, pluginstate.SlotA)
	require.ErrorIs(t, err, ErrInstallFailed)

	var validArchive []byte
	var validPublicKey ed25519.PublicKey
	var validManifestDigest []byte
	if fixturePath := os.Getenv("DBPILOT_PLUGIN_PROCESS_FIXTURE"); fixturePath != "" {
		validArchive, validPublicKey, validManifestDigest = signedSingleBinaryArchive(t, requireReadFile(t, fixturePath))
	} else {
		validArchive, validPublicKey, validManifestDigest = sharedCorpusArchive(t)
	}
	validDigest := sha256.Sum256(validArchive)
	root := t.TempDir()
	installer = newTestInstaller(t, root, validPublicKey)
	installed, err := installer.InstallInactive(context.Background(), InstallRequest{DatabaseFamily: "mysql", PluginID: "mysql", Version: "1.0.0", ArtifactSHA256: validDigest[:], ManifestDigest: validManifestDigest, Archive: bytes.NewReader(validArchive), ArchiveSize: int64(len(validArchive))}, pluginstate.SlotA)
	require.NoError(t, err)
	outsideLink := filepath.Join(root, "unexpected-hardlink")
	if linkErr := os.Link(installed.ExecutablePath, outsideLink); linkErr == nil {
		if runtime.GOOS == "linux" {
			require.ErrorIs(t, installer.Activate(context.Background(), SlotIdentity{DatabaseFamily: "mysql", PluginID: "mysql", Version: "1.0.0", ArtifactSHA256: hex.EncodeToString(validDigest[:]), ManifestDigest: hex.EncodeToString(validManifestDigest)}, pluginstate.SlotA), ErrInstallFailed)
		}
	}
}

func TestInstallerReauthenticatesRetainedPackageAndRejectsSameUIDTamper(t *testing.T) {
	var archive []byte
	var publicKey ed25519.PublicKey
	var manifestDigest []byte
	if fixturePath := os.Getenv("DBPILOT_PLUGIN_PROCESS_FIXTURE"); fixturePath != "" {
		archive, publicKey, manifestDigest = signedSingleBinaryArchive(t, requireReadFile(t, fixturePath))
	} else {
		archive, publicKey, manifestDigest = sharedCorpusArchive(t)
	}
	artifactDigest := sha256.Sum256(archive)
	identity := SlotIdentity{DatabaseFamily: "mysql", PluginID: "mysql", Version: "1.0.0", ArtifactSHA256: hex.EncodeToString(artifactDigest[:]), ManifestDigest: hex.EncodeToString(manifestDigest)}
	root := t.TempDir()
	installer := newTestInstaller(t, root, publicKey)
	installed, err := installer.InstallInactive(context.Background(), InstallRequest{DatabaseFamily: "mysql", PluginID: "mysql", Version: "1.0.0", ArtifactSHA256: artifactDigest[:], ManifestDigest: manifestDigest, Archive: bytes.NewReader(archive), ArchiveSize: int64(len(archive))}, pluginstate.SlotA)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(installed.ExecutablePath, 0o600))
	require.NoError(t, os.WriteFile(installed.ExecutablePath, []byte("attacker executable"), 0o600))
	require.NoError(t, os.Chmod(installed.ExecutablePath, 0o500))
	require.NoError(t, os.Chmod(filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(installed.ExecutablePath))), completionMarkerName), 0o600))
	_, err = installer.Installed(context.Background(), identity, pluginstate.SlotA)
	require.Error(t, err)

	root = t.TempDir()
	installer = newTestInstaller(t, root, publicKey)
	installed, err = installer.InstallInactive(context.Background(), InstallRequest{DatabaseFamily: "mysql", PluginID: "mysql", Version: "1.0.0", ArtifactSHA256: artifactDigest[:], ManifestDigest: manifestDigest, Archive: bytes.NewReader(archive), ArchiveSize: int64(len(archive))}, pluginstate.SlotA)
	require.NoError(t, err)
	archivePath := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(installed.ExecutablePath))), retainedArchiveName)
	require.NoError(t, os.Chmod(archivePath, 0o600))
	body := requireReadFile(t, archivePath)
	body[len(body)/2] ^= 0xff
	require.NoError(t, os.WriteFile(archivePath, body, 0o600))
	require.NoError(t, os.Chmod(archivePath, 0o400))
	_, err = installer.Installed(context.Background(), identity, pluginstate.SlotA)
	require.Error(t, err)
}

func newTestInstaller(t *testing.T, root string, publicKey ed25519.PublicKey) *Installer {
	t.Helper()
	publishers, err := plugincatalog.NewStaticPublisherKeyStore([]plugincatalog.PublisherKey{{PublisherID: "fixture-publisher", KeyID: "fixture-key", PublicKey: publicKey}})
	require.NoError(t, err)
	installer, err := NewInstaller(InstallerConfig{Root: root, Publishers: publishers, OperatingSystem: "linux", Architecture: "amd64", Limits: plugincatalog.DefaultPackageLimits()})
	require.NoError(t, err)
	return installer
}

func sharedCorpusArchive(t *testing.T) ([]byte, ed25519.PublicKey, []byte) {
	t.Helper()
	base := filepath.Join("..", "..", "plugincatalog", "testdata", "package-v1")
	manifest := bytes.TrimSuffix(requireReadFile(t, filepath.Join(base, "manifest.json")), []byte("\n"))
	amd64ELF, err := hex.DecodeString(string(bytes.TrimSpace(requireReadFile(t, filepath.Join(base, "linux-amd64.elf.hex")))))
	require.NoError(t, err)
	arm64ELF, err := hex.DecodeString(string(bytes.TrimSpace(requireReadFile(t, filepath.Join(base, "linux-arm64.elf.hex")))))
	require.NoError(t, err)
	var vectors struct {
		PublicKeyHex   string `json:"public_key_hex"`
		SignatureHex   string `json:"signature_hex"`
		ManifestDigest string `json:"manifest_digest"`
	}
	require.NoError(t, json.Unmarshal(requireReadFile(t, filepath.Join(base, "vectors.json")), &vectors))
	publicKey, err := hex.DecodeString(vectors.PublicKeyHex)
	require.NoError(t, err)
	signature, err := hex.DecodeString(vectors.SignatureHex)
	require.NoError(t, err)
	manifestDigest, err := hex.DecodeString(vectors.ManifestDigest)
	require.NoError(t, err)
	archive := tarGzip(t, []archiveEntry{
		{name: "plugin-package/", directory: true},
		{name: "plugin-package/bin/", directory: true},
		{name: "plugin-package/bin/linux-amd64/", directory: true},
		{name: "plugin-package/bin/linux-arm64/", directory: true},
		{name: "plugin-package/manifest.json", body: manifest, mode: 0o600},
		{name: "plugin-package/bin/linux-amd64/dbpilot-plugin-mysql", body: amd64ELF, mode: 0o755},
		{name: "plugin-package/bin/linux-arm64/dbpilot-plugin-mysql", body: arm64ELF, mode: 0o755},
		{name: "plugin-package/SIGNATURE.ed25519", body: signature, mode: 0o600},
	})
	return archive, ed25519.PublicKey(publicKey), manifestDigest
}

type archiveEntry struct {
	name      string
	body      []byte
	mode      int64
	directory bool
}

func tarGzip(t *testing.T, entries []archiveEntry) []byte {
	t.Helper()
	var result bytes.Buffer
	gzipWriter := gzip.NewWriter(&result)
	gzipWriter.Header.ModTime = time.Unix(0, 0)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Mode: entry.mode, Size: int64(len(entry.body)), Typeflag: tar.TypeReg}
		if entry.directory {
			header.Typeflag, header.Mode, header.Size = tar.TypeDir, 0o700, 0
		}
		require.NoError(t, tarWriter.WriteHeader(header))
		if len(entry.body) > 0 {
			_, err := tarWriter.Write(entry.body)
			require.NoError(t, err)
		}
	}
	require.NoError(t, tarWriter.Close())
	require.NoError(t, gzipWriter.Close())
	return result.Bytes()
}

func malformedArchive(t *testing.T, headers []tar.Header) []byte {
	t.Helper()
	var result bytes.Buffer
	gzipWriter := gzip.NewWriter(&result)
	tarWriter := tar.NewWriter(gzipWriter)
	for index := range headers {
		header := headers[index]
		require.NoError(t, tarWriter.WriteHeader(&header))
		if header.Size > 0 {
			_, err := tarWriter.Write(bytes.Repeat([]byte{'x'}, int(header.Size)))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tarWriter.Close())
	require.NoError(t, gzipWriter.Close())
	return result.Bytes()
}

func requireReadFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	return body
}

func signedCaseCollisionArchive(t *testing.T) ([]byte, ed25519.PublicKey, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	var executable []byte
	if fixturePath := os.Getenv("DBPILOT_PLUGIN_PROCESS_FIXTURE"); fixturePath != "" {
		executable = requireReadFile(t, fixturePath)
	} else {
		base := filepath.Join("..", "..", "plugincatalog", "testdata", "package-v1")
		executable, err = hex.DecodeString(string(bytes.TrimSpace(requireReadFile(t, filepath.Join(base, "linux-amd64.elf.hex")))))
		require.NoError(t, err)
	}
	digest := sha256.Sum256(executable)
	lower := "plugin-package/bin/linux-amd64/dbpilot-plugin-mysql"
	upper := "plugin-package/bin/linux-amd64/DBPILOT-PLUGIN-MYSQL"
	manifest := map[string]any{"plugin_id": "mysql", "database_family": "mysql", "version": "1.0.0", "protocol_version": "v1", "publisher_id": "fixture-publisher", "signing_key_id": "fixture-key", "minimum_agent_protocol_version": "v1", "maximum_agent_protocol_version": "v1", "supported_variants": []string{"mysql"}, "database_version_range": ">=8 <9", "capabilities": []string{"metrics.collect"}, "metric_template_schema_version": 1, "binaries": []map[string]any{{"operating_system": "linux", "architecture": "amd64", "path": lower, "sha256": hex.EncodeToString(digest[:]), "size_bytes": len(executable)}}, "files": []map[string]any{{"path": lower, "sha256": hex.EncodeToString(digest[:]), "size_bytes": len(executable)}, {"path": upper, "sha256": hex.EncodeToString(digest[:]), "size_bytes": len(executable)}}}
	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)
	manifestDigest := sha256.Sum256(manifestBytes)
	regular := map[string][]byte{"plugin-package/manifest.json": manifestBytes, lower: executable, upper: executable}
	paths := make([]string, 0, len(regular))
	for name := range regular {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	hash := sha256.New()
	_, _ = io.WriteString(hash, "dbpilot-plugin-content-v1\n")
	for _, name := range paths {
		entryDigest := sha256.Sum256(regular[name])
		for _, value := range []string{name, strconv.Itoa(len(regular[name])), hex.EncodeToString(entryDigest[:])} {
			_, _ = io.WriteString(hash, strconv.Itoa(len(value))+":"+value)
		}
	}
	contentDigest := hash.Sum(nil)
	signature := ed25519.Sign(privateKey, []byte("dbpilot-plugin-signature-v1\nmanifest-sha256:"+hex.EncodeToString(manifestDigest[:])+"\ncontent-sha256:"+hex.EncodeToString(contentDigest)+"\n"))
	archive := tarGzip(t, []archiveEntry{{name: "plugin-package/manifest.json", body: manifestBytes, mode: 0o400}, {name: lower, body: executable, mode: 0o500}, {name: upper, body: executable, mode: 0o500}, {name: "plugin-package/SIGNATURE.ed25519", body: signature, mode: 0o400}})
	return archive, publicKey, manifestDigest[:]
}

func signedSingleBinaryArchive(t *testing.T, executable []byte) ([]byte, ed25519.PublicKey, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	digest := sha256.Sum256(executable)
	binaryPath := "plugin-package/bin/linux-amd64/dbpilot-plugin-mysql"
	manifest := map[string]any{"plugin_id": "mysql", "database_family": "mysql", "version": "1.0.0", "protocol_version": "v1", "publisher_id": "fixture-publisher", "signing_key_id": "fixture-key", "minimum_agent_protocol_version": "v1", "maximum_agent_protocol_version": "v1", "supported_variants": []string{"mysql"}, "database_version_range": ">=8 <9", "capabilities": []string{"metrics.collect"}, "metric_template_schema_version": 1, "binaries": []map[string]any{{"operating_system": "linux", "architecture": "amd64", "path": binaryPath, "sha256": hex.EncodeToString(digest[:]), "size_bytes": len(executable)}}, "files": []map[string]any{{"path": binaryPath, "sha256": hex.EncodeToString(digest[:]), "size_bytes": len(executable)}}}
	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)
	manifestDigest := sha256.Sum256(manifestBytes)
	regular := map[string][]byte{"plugin-package/manifest.json": manifestBytes, binaryPath: executable}
	paths := []string{"plugin-package/manifest.json", binaryPath}
	sort.Strings(paths)
	hash := sha256.New()
	_, _ = io.WriteString(hash, "dbpilot-plugin-content-v1\n")
	for _, name := range paths {
		entryDigest := sha256.Sum256(regular[name])
		for _, value := range []string{name, strconv.Itoa(len(regular[name])), hex.EncodeToString(entryDigest[:])} {
			_, _ = io.WriteString(hash, strconv.Itoa(len(value))+":"+value)
		}
	}
	signature := ed25519.Sign(privateKey, []byte("dbpilot-plugin-signature-v1\nmanifest-sha256:"+hex.EncodeToString(manifestDigest[:])+"\ncontent-sha256:"+hex.EncodeToString(hash.Sum(nil))+"\n"))
	archive := tarGzip(t, []archiveEntry{{name: "plugin-package/manifest.json", body: manifestBytes, mode: 0o400}, {name: binaryPath, body: executable, mode: 0o500}, {name: "plugin-package/SIGNATURE.ed25519", body: signature, mode: 0o400}})
	return archive, publicKey, manifestDigest[:]
}
