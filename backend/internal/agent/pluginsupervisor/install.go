package pluginsupervisor

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"dbpilot.local/platform/internal/agent/pluginstate"
	"dbpilot.local/platform/internal/plugincatalog"
)

const (
	slotsDirectoryName   = "slots"
	activeMarkerName     = "active.json"
	completionMarkerName = ".complete.json"
	retainedArchiveName  = ".package.tar.gz"
	packageRootName      = "plugin-package"
)

type InstallerConfig struct {
	Root            string
	Publishers      plugincatalog.PublisherKeyStore
	OperatingSystem string
	Architecture    string
	Limits          plugincatalog.PackageLimits
	Now             func() time.Time
}

type Installer struct {
	root            string
	verifier        *plugincatalog.StreamingPackageVerifier
	operatingSystem string
	architecture    string
	now             func() time.Time
}

type completionRecord struct {
	PluginID         string `json:"plugin_id"`
	DatabaseFamily   string `json:"database_family"`
	Version          string `json:"version"`
	ArtifactSHA256   string `json:"artifact_sha256"`
	ManifestDigest   string `json:"manifest_digest"`
	ExecutablePath   string `json:"executable_path"`
	ExecutableSHA256 string `json:"executable_sha256"`
	CompletedAt      string `json:"completed_at"`
}

type activeRecord struct {
	Slot pluginstate.Slot `json:"slot"`
}

func NewInstaller(config InstallerConfig) (*Installer, error) {
	if !filepath.IsAbs(config.Root) || filepath.Clean(config.Root) != config.Root || config.Publishers == nil || config.OperatingSystem != "linux" || config.Architecture != "amd64" && config.Architecture != "arm64" {
		return nil, ErrInstallFailed
	}
	info, err := os.Lstat(config.Root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInstallFailed
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(config.Root, 0o700); err != nil {
			return nil, ErrInstallFailed
		}
	}
	temporary := filepath.Join(config.Root, ".verify-cache")
	if err := secureMkdir(config.Root, temporary); err != nil {
		return nil, ErrInstallFailed
	}
	verifier, err := plugincatalog.NewStreamingPackageVerifier(plugincatalog.PackageVerifierConfig{Publishers: config.Publishers, TemporaryDirectory: temporary, Limits: config.Limits})
	if err != nil {
		return nil, ErrInstallFailed
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Installer{root: config.Root, verifier: verifier, operatingSystem: config.OperatingSystem, architecture: config.Architecture, now: config.Now}, nil
}

func (installer *Installer) InstallInactive(ctx context.Context, request InstallRequest, slot pluginstate.Slot) (InstalledSlot, error) {
	if installer == nil || ctx == nil || ctx.Err() != nil || request.Archive == nil || request.ArchiveSize <= 0 || !familyIdentifier.MatchString(request.DatabaseFamily) || !familyIdentifier.MatchString(request.PluginID) || !boundedVersion(request.Version) || len(request.ArtifactSHA256) != sha256.Size || len(request.ManifestDigest) != sha256.Size || slot != pluginstate.SlotA && slot != pluginstate.SlotB {
		return InstalledSlot{}, ErrInstallFailed
	}
	if active, err := installer.ActiveSlot(request.DatabaseFamily); err != nil {
		return InstalledSlot{}, err
	} else if active == slot {
		return InstalledSlot{}, ErrInstallFailed
	}
	verified, err := installer.verifier.Verify(ctx, request.Archive, request.ArchiveSize)
	if err != nil {
		return InstalledSlot{}, classifyVerificationError(err)
	}
	defer verified.Close()
	wantArtifact := hex.EncodeToString(request.ArtifactSHA256)
	wantManifest := hex.EncodeToString(request.ManifestDigest)
	if verified.PackageSHA256 != wantArtifact {
		return InstalledSlot{}, ErrArtifactDigest
	}
	if verified.ManifestDigest != wantManifest {
		return InstalledSlot{}, ErrManifestRejected
	}
	manifest := verified.Manifest
	if manifest.PluginID != request.PluginID || manifest.DatabaseFamily != request.DatabaseFamily || manifest.Version != request.Version {
		return InstalledSlot{}, ErrManifestRejected
	}
	binaryPath, binaryDigest, ok := platformBinary(manifest, installer.operatingSystem, installer.architecture)
	if !ok {
		return InstalledSlot{}, ErrPlatformMismatch
	}

	familyRoot := filepath.Join(installer.root, request.DatabaseFamily)
	slotsRoot := filepath.Join(familyRoot, slotsDirectoryName)
	if err := secureMkdir(installer.root, familyRoot); err != nil {
		return InstalledSlot{}, ErrInstallFailed
	}
	if err := secureMkdir(installer.root, slotsRoot); err != nil {
		return InstalledSlot{}, ErrInstallFailed
	}
	target := filepath.Join(slotsRoot, string(slot))
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return InstalledSlot{}, ErrInstallFailed
	}
	stage, err := os.MkdirTemp(familyRoot, ".install-")
	if err != nil {
		return InstalledSlot{}, ErrInstallFailed
	}
	if err := os.Chmod(stage, 0o700); err != nil {
		_ = safeRemoveTree(familyRoot, stage)
		return InstalledSlot{}, ErrInstallFailed
	}
	committed := false
	defer func() {
		if !committed {
			_ = safeRemoveTree(familyRoot, stage)
		}
	}()
	archiveSource, err := verified.Open()
	if err != nil {
		return InstalledSlot{}, ErrInstallFailed
	}
	archivePath := filepath.Join(stage, retainedArchiveName)
	archiveFile, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
	if err != nil {
		_ = archiveSource.Close()
		return InstalledSlot{}, ErrInstallFailed
	}
	archiveHash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(archiveFile, archiveHash), archiveSource)
	archiveErr := errors.Join(copyErr, archiveFile.Sync(), archiveFile.Chmod(0o400), archiveFile.Close(), archiveSource.Close())
	if archiveErr != nil || written != request.ArchiveSize || hex.EncodeToString(archiveHash.Sum(nil)) != wantArtifact {
		return InstalledSlot{}, ErrInstallFailed
	}

	source, err := verified.Open()
	if err != nil {
		return InstalledSlot{}, ErrInstallFailed
	}
	extractErr := extractVerifiedArchive(ctx, source, stage)
	closeErr := source.Close()
	if extractErr != nil || closeErr != nil {
		return InstalledSlot{}, ErrInstallFailed
	}
	relativeExecutable := strings.TrimPrefix(binaryPath, packageRootName+"/")
	executable := filepath.Join(stage, filepath.FromSlash(relativeExecutable))
	manifestPath := filepath.Join(stage, "manifest.json")
	if err := requirePrivateRegular(executable, 0o500); err != nil {
		return InstalledSlot{}, ErrInstallFailed
	}
	if err := requirePrivateRegular(manifestPath, 0o400); err != nil {
		return InstalledSlot{}, ErrInstallFailed
	}
	record := completionRecord{PluginID: request.PluginID, DatabaseFamily: request.DatabaseFamily, Version: request.Version, ArtifactSHA256: wantArtifact, ManifestDigest: wantManifest, ExecutablePath: filepath.ToSlash(relativeExecutable), ExecutableSHA256: binaryDigest, CompletedAt: installer.now().UTC().Format(time.RFC3339Nano)}
	if err := writeExclusiveJSON(filepath.Join(stage, completionMarkerName), record, 0o400); err != nil {
		return InstalledSlot{}, ErrInstallFailed
	}
	if err := syncTree(stage); err != nil {
		return InstalledSlot{}, ErrInstallFailed
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return InstalledSlot{}, ErrInstallFailed
	}
	if err := os.Rename(stage, target); err != nil {
		return InstalledSlot{}, ErrInstallFailed
	}
	if err := syncDirectoryPath(slotsRoot); err != nil {
		return InstalledSlot{}, ErrInstallFailed
	}
	committed = true
	return InstalledSlot{Slot: slot, Version: request.Version, ExecutablePath: filepath.Join(target, filepath.FromSlash(relativeExecutable)), ExecutableSHA256: binaryDigest, ManifestPath: filepath.Join(target, "manifest.json"), ArtifactSHA256: wantArtifact, ManifestDigest: wantManifest}, nil
}

func (installer *Installer) ActiveSlot(family string) (pluginstate.Slot, error) {
	if installer == nil || !familyIdentifier.MatchString(family) {
		return pluginstate.SlotNone, ErrInstallFailed
	}
	marker := filepath.Join(installer.root, family, activeMarkerName)
	info, err := os.Lstat(marker)
	if errors.Is(err, os.ErrNotExist) {
		return pluginstate.SlotNone, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 64 {
		return pluginstate.SlotNone, ErrInstallFailed
	}
	body, err := os.ReadFile(marker)
	if err != nil {
		return pluginstate.SlotNone, ErrInstallFailed
	}
	var record activeRecord
	if json.Unmarshal(body, &record) != nil || record.Slot != pluginstate.SlotA && record.Slot != pluginstate.SlotB {
		return pluginstate.SlotNone, ErrInstallFailed
	}
	if err := requireCompletedSlot(filepath.Join(installer.root, family, slotsDirectoryName, string(record.Slot))); err != nil {
		return pluginstate.SlotNone, err
	}
	return record.Slot, nil
}

func (installer *Installer) Installed(ctx context.Context, expected SlotIdentity, slot pluginstate.Slot) (InstalledSlot, error) {
	if installer == nil || ctx == nil || ctx.Err() != nil || !familyIdentifier.MatchString(expected.DatabaseFamily) || !familyIdentifier.MatchString(expected.PluginID) || !boundedVersion(expected.Version) || len(expected.ArtifactSHA256) != 64 || len(expected.ManifestDigest) != 64 || slot != pluginstate.SlotA && slot != pluginstate.SlotB {
		return InstalledSlot{}, ErrInstallFailed
	}
	root := filepath.Join(installer.root, expected.DatabaseFamily, slotsDirectoryName, string(slot))
	if err := requireCompletedSlot(root); err != nil {
		return InstalledSlot{}, err
	}
	archivePath := filepath.Join(root, retainedArchiveName)
	info, err := os.Lstat(archivePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm() != 0o400 || linkCount(info) > 1 || info.Size() <= 0 {
		return InstalledSlot{}, ErrInstallFailed
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return InstalledSlot{}, ErrInstallFailed
	}
	verified, verifyErr := installer.verifier.Verify(ctx, archive, info.Size())
	closeErr := archive.Close()
	if verifyErr != nil || closeErr != nil {
		return InstalledSlot{}, classifyVerificationError(verifyErr)
	}
	defer verified.Close()
	if verified.PackageSHA256 != expected.ArtifactSHA256 || verified.ManifestDigest != expected.ManifestDigest || verified.Manifest.PluginID != expected.PluginID || verified.Manifest.DatabaseFamily != expected.DatabaseFamily || verified.Manifest.Version != expected.Version {
		return InstalledSlot{}, ErrManifestRejected
	}
	binaryPath, binaryDigest, ok := platformBinary(verified.Manifest, installer.operatingSystem, installer.architecture)
	if !ok || verifyInstalledFiles(root, verified.Manifest, binaryPath, expected.ManifestDigest) != nil {
		return InstalledSlot{}, ErrInstallFailed
	}
	relativeExecutable := strings.TrimPrefix(binaryPath, packageRootName+"/")
	executable := filepath.Join(root, filepath.FromSlash(relativeExecutable))
	if !withinRoot(root, executable) || requirePrivateRegular(executable, 0o500) != nil {
		return InstalledSlot{}, ErrInstallFailed
	}
	return InstalledSlot{Slot: slot, Version: expected.Version, ExecutablePath: executable, ExecutableSHA256: binaryDigest, ManifestPath: filepath.Join(root, "manifest.json"), ArtifactSHA256: expected.ArtifactSHA256, ManifestDigest: expected.ManifestDigest}, nil
}

func verifyInstalledFiles(root string, manifest plugincatalog.Manifest, binaryPath, manifestDigest string) error {
	for _, declared := range manifest.Files {
		relative := strings.TrimPrefix(declared.Path, packageRootName+"/")
		path := filepath.Join(root, filepath.FromSlash(relative))
		mode := os.FileMode(0o400)
		if declared.Path == binaryPath || strings.HasPrefix(relative, "bin/") {
			mode = 0o500
		}
		if err := requirePrivateRegular(path, mode); err != nil {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		hash := sha256.New()
		size, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || size != declared.SizeBytes || hex.EncodeToString(hash.Sum(nil)) != declared.SHA256 {
			return ErrInstallFailed
		}
	}
	manifestBytes, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(manifestBytes)
	if hex.EncodeToString(digest[:]) != manifestDigest {
		return ErrInstallFailed
	}
	return nil
}

func (installer *Installer) Activate(ctx context.Context, identity SlotIdentity, slot pluginstate.Slot) error {
	if installer == nil || ctx == nil || ctx.Err() != nil || !familyIdentifier.MatchString(identity.DatabaseFamily) || slot != pluginstate.SlotA && slot != pluginstate.SlotB {
		return ErrInstallFailed
	}
	if _, err := installer.Installed(ctx, identity, slot); err != nil {
		return err
	}
	familyRoot := filepath.Join(installer.root, identity.DatabaseFamily)
	if err := requireCompletedSlot(filepath.Join(familyRoot, slotsDirectoryName, string(slot))); err != nil {
		return err
	}
	marker := filepath.Join(familyRoot, activeMarkerName)
	temporary := marker + ".tmp"
	if err := removePrivateRegular(temporary); err != nil {
		return ErrInstallFailed
	}
	if err := writeExclusiveJSON(temporary, activeRecord{Slot: slot}, 0o400); err != nil {
		return ErrInstallFailed
	}
	if runtime.GOOS == "windows" {
		if err := removePrivateRegular(marker); err != nil {
			_ = os.Remove(temporary)
			return ErrInstallFailed
		}
	}
	if err := os.Rename(temporary, marker); err != nil {
		_ = os.Remove(temporary)
		return ErrInstallFailed
	}
	return syncDirectoryPath(familyRoot)
}

func (installer *Installer) RemoveInactive(ctx context.Context, family string, slot pluginstate.Slot) error {
	if installer == nil || ctx == nil || ctx.Err() != nil || !familyIdentifier.MatchString(family) || slot != pluginstate.SlotA && slot != pluginstate.SlotB {
		return ErrInstallFailed
	}
	active, err := installer.ActiveSlot(family)
	if err != nil {
		return err
	}
	if active == slot {
		return ErrInstallFailed
	}
	target := filepath.Join(installer.root, family, slotsDirectoryName, string(slot))
	if err := safeRemoveTree(filepath.Join(installer.root, family), target); err != nil {
		return ErrInstallFailed
	}
	parent := filepath.Dir(target)
	if info, err := os.Lstat(parent); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInstallFailed
	}
	return syncDirectoryPath(parent)
}

func (installer *Installer) RemoveFamily(ctx context.Context, family string) error {
	if installer == nil || ctx == nil || ctx.Err() != nil || !familyIdentifier.MatchString(family) {
		return ErrInstallFailed
	}
	target := filepath.Join(installer.root, family)
	if err := safeRemoveTree(installer.root, target); err != nil {
		return ErrInstallFailed
	}
	return syncDirectoryPath(installer.root)
}

func (installer *Installer) Recover(ctx context.Context, family string) error {
	if installer == nil || ctx == nil || ctx.Err() != nil || !familyIdentifier.MatchString(family) {
		return ErrInstallFailed
	}
	familyRoot := filepath.Join(installer.root, family)
	entries, err := os.ReadDir(familyRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrInstallFailed
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".install-") {
			if err := safeRemoveTree(familyRoot, filepath.Join(familyRoot, entry.Name())); err != nil {
				return ErrInstallFailed
			}
		}
	}
	if _, err := installer.ActiveSlot(family); err != nil {
		return err
	}
	return syncDirectoryPath(familyRoot)
}

func extractVerifiedArchive(ctx context.Context, source io.Reader, target string) error {
	buffered := bufio.NewReader(source)
	gzipReader, err := gzip.NewReader(buffered)
	if err != nil {
		return err
	}
	gzipReader.Multistream(false)
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	seen := map[string]struct{}{}
	caseFolded := map[string]struct{}{}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil || header == nil || header.Mode&0o7000 != 0 {
			return ErrInstallFailed
		}
		name, err := installArchivePath(header.Name, header.Typeflag == tar.TypeDir)
		if err != nil {
			return err
		}
		folded := strings.ToLower(name)
		if _, duplicate := seen[name]; duplicate {
			return ErrInstallFailed
		}
		if _, collision := caseFolded[folded]; collision {
			return ErrInstallFailed
		}
		seen[name], caseFolded[folded] = struct{}{}, struct{}{}
		relative := strings.TrimPrefix(name, packageRootName)
		relative = strings.TrimPrefix(relative, "/")
		if relative == "" {
			continue
		}
		destination := filepath.Join(target, filepath.FromSlash(relative))
		if !withinRoot(target, destination) {
			return ErrInstallFailed
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 || secureMkdir(target, destination) != nil {
				return ErrInstallFailed
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size <= 0 || secureMkdir(target, filepath.Dir(destination)) != nil {
				return ErrInstallFailed
			}
			mode := os.FileMode(0o400)
			if strings.HasPrefix(relative, "bin/") {
				mode = 0o500
			}
			file, openErr := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if openErr != nil {
				return ErrInstallFailed
			}
			copied, copyErr := io.CopyN(file, tarReader, header.Size)
			syncErr := file.Sync()
			chmodErr := file.Chmod(mode)
			closeErr := file.Close()
			if copyErr != nil || copied != header.Size || syncErr != nil || chmodErr != nil || closeErr != nil {
				return ErrInstallFailed
			}
		default:
			return ErrInstallFailed
		}
	}
	return nil
}

func installArchivePath(value string, directory bool) (string, error) {
	if value == "" || strings.ContainsAny(value, "\\:\x00") || path.IsAbs(value) || filepath.IsAbs(value) || filepath.VolumeName(value) != "" {
		return "", ErrInstallFailed
	}
	trimmed := value
	if directory {
		trimmed = strings.TrimSuffix(trimmed, "/")
	}
	if trimmed == "" || path.Clean(trimmed) != trimmed || trimmed != packageRootName && !strings.HasPrefix(trimmed, packageRootName+"/") {
		return "", ErrInstallFailed
	}
	for _, component := range strings.Split(trimmed, "/") {
		if component == "" || component == "." || component == ".." || strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") {
			return "", ErrInstallFailed
		}
	}
	return trimmed, nil
}

func platformBinary(manifest plugincatalog.Manifest, operatingSystem, architecture string) (string, string, bool) {
	for _, binary := range manifest.Binaries {
		if binary.OperatingSystem == operatingSystem && binary.Architecture == architecture {
			return binary.Path, binary.SHA256, true
		}
	}
	return "", "", false
}

func classifyVerificationError(err error) error {
	switch {
	case errors.Is(err, plugincatalog.ErrSignatureRejected), errors.Is(err, plugincatalog.ErrUnknownPublisher):
		return ErrSignatureRejected
	case errors.Is(err, plugincatalog.ErrPlatformMismatch):
		return ErrPlatformMismatch
	case errors.Is(err, plugincatalog.ErrManifestRejected), errors.Is(err, plugincatalog.ErrPackageTooLarge):
		return ErrManifestRejected
	default:
		return ErrInstallFailed
	}
}

func secureMkdir(root, target string) error {
	if !withinRoot(root, target) {
		return ErrInstallFailed
	}
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return err
	}
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "." || component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			if mkdirErr := os.Mkdir(current, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
				return mkdirErr
			}
			info, statErr = os.Lstat(current)
		}
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrInstallFailed
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
			if err := os.Chmod(current, 0o700); err != nil {
				return err
			}
		}
	}
	return nil
}

func withinRoot(root, target string) bool {
	relative, err := filepath.Rel(root, target)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func writeExclusiveJSON(path string, value any, mode os.FileMode) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > 4096 {
		return ErrInstallFailed
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(encoded)
	syncErr := file.Sync()
	chmodErr := file.Chmod(mode)
	closeErr := file.Close()
	return errors.Join(writeErr, syncErr, chmodErr, closeErr)
}

func requirePrivateRegular(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || linkCount(info) > 1 {
		return ErrInstallFailed
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != mode {
		return ErrInstallFailed
	}
	return nil
}

func requireCompletedSlot(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInstallFailed
	}
	marker := filepath.Join(path, completionMarkerName)
	if err := requirePrivateRegular(marker, 0o400); err != nil {
		return err
	}
	return validateTree(path)
}

func validateTree(root string) error {
	caseFolded := map[string]struct{}{}
	return filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrInstallFailed
		}
		relative, err := filepath.Rel(root, current)
		if err != nil || !withinRoot(root, current) {
			return ErrInstallFailed
		}
		folded := strings.ToLower(filepath.ToSlash(relative))
		if _, collision := caseFolded[folded]; collision {
			return ErrInstallFailed
		}
		caseFolded[folded] = struct{}{}
		if info.Mode().IsRegular() && linkCount(info) > 1 {
			return ErrInstallFailed
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return ErrInstallFailed
		}
		return nil
	})
}

func safeRemoveTree(root, target string) error {
	if !withinRoot(root, target) || filepath.Clean(root) == filepath.Clean(target) {
		return ErrInstallFailed
	}
	if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := validateTree(target); err != nil {
		return err
	}
	return os.RemoveAll(target)
}

func removePrivateRegular(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || linkCount(info) > 1 {
		return ErrInstallFailed
	}
	return os.Remove(path)
}

func linkCount(info os.FileInfo) uint64 {
	if info == nil || info.Sys() == nil {
		return 1
	}
	value := reflect.Indirect(reflect.ValueOf(info.Sys()))
	if !value.IsValid() {
		return 1
	}
	field := value.FieldByName("Nlink")
	if !field.IsValid() {
		return 1
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return field.Uint()
	default:
		return 1
	}
}

func syncTree(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			directories = append(directories, current)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(directories, func(left, right int) bool { return len(directories[left]) > len(directories[right]) })
	for _, directory := range directories {
		if err := syncDirectoryPath(directory); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectoryPath(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

var _ SlotInstaller = (*Installer)(nil)
