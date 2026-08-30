package plugincatalog

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const (
	manifestPath  = "plugin-package/manifest.json"
	signaturePath = "plugin-package/SIGNATURE.ed25519"
)

type PackageVerifier interface {
	Verify(context.Context, io.Reader, int64) (VerifiedPackage, error)
}

type PackageLimits struct {
	MaxCompressedBytes int64
	MaxExpandedBytes   int64
	MaxFileBytes       int64
	MaxFiles           int
	MaxManifestBytes   int64
}

type PackageVerifierConfig struct {
	Publishers         PublisherKeyStore
	TemporaryDirectory string
	Limits             PackageLimits
}

type StreamingPackageVerifier struct {
	publishers PublisherKeyStore
	temporary  string
	limits     PackageLimits
}

func DefaultPackageLimits() PackageLimits {
	return PackageLimits{
		MaxCompressedBytes: 256 << 20,
		MaxExpandedBytes:   1 << 30,
		MaxFileBytes:       512 << 20,
		MaxFiles:           4096,
		MaxManifestBytes:   1 << 20,
	}
}

type verifiedEntry struct {
	path   string
	size   int64
	digest [sha256.Size]byte
}

func NewStreamingPackageVerifier(config PackageVerifierConfig) (*StreamingPackageVerifier, error) {
	if config.Publishers == nil || config.TemporaryDirectory == "" || !validPackageLimits(config.Limits) {
		return nil, ErrInvalid
	}
	info, err := os.Stat(config.TemporaryDirectory)
	if err != nil || !info.IsDir() {
		return nil, ErrInvalid
	}
	return &StreamingPackageVerifier{publishers: config.Publishers, temporary: config.TemporaryDirectory, limits: config.Limits}, nil
}

func validPackageLimits(value PackageLimits) bool {
	return value.MaxCompressedBytes > 0 && value.MaxCompressedBytes <= 256<<20 &&
		value.MaxExpandedBytes > 0 && value.MaxExpandedBytes <= 1<<30 &&
		value.MaxFileBytes > 0 && value.MaxFileBytes <= 1<<30 &&
		value.MaxFiles >= 3 && value.MaxFiles <= 4096 &&
		value.MaxManifestBytes > 0 && value.MaxManifestBytes <= 1<<20 && value.MaxManifestBytes <= value.MaxFileBytes
}

func (verifier *StreamingPackageVerifier) Verify(ctx context.Context, source io.Reader, declaredBytes int64) (VerifiedPackage, error) {
	if verifier == nil || ctx == nil || source == nil || declaredBytes <= 0 {
		return VerifiedPackage{}, beforeSideEffect(ErrManifestRejected)
	}
	if declaredBytes > verifier.limits.MaxCompressedBytes {
		return VerifiedPackage{}, beforeSideEffect(ErrPackageTooLarge)
	}
	temporary, err := os.CreateTemp(verifier.temporary, ".dbpilot-plugin-upload-*")
	if err != nil {
		return VerifiedPackage{}, ErrArtifactUnavailable
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	packageHash := sha256.New()
	limited := &io.LimitedReader{R: source, N: declaredBytes + 1}
	written, copyErr := copyWithContext(ctx, io.MultiWriter(temporary, packageHash), limited)
	if copyErr != nil {
		cleanup()
		if ctx.Err() != nil {
			return VerifiedPackage{}, ctx.Err()
		}
		return VerifiedPackage{}, beforeSideEffect(ErrManifestRejected)
	}
	if written != declaredBytes {
		cleanup()
		if written > declaredBytes {
			return VerifiedPackage{}, beforeSideEffect(ErrPackageTooLarge)
		}
		return VerifiedPackage{}, beforeSideEffect(ErrManifestRejected)
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return VerifiedPackage{}, ErrArtifactUnavailable
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return VerifiedPackage{}, ErrArtifactUnavailable
	}
	manifestBytes, signature, entries, err := verifier.inspectArchive(ctx, temporary)
	if err != nil {
		cleanup()
		return VerifiedPackage{}, beforeSideEffect(err)
	}
	manifest, canonical, err := decodeCanonicalManifest(manifestBytes)
	if err != nil {
		cleanup()
		return VerifiedPackage{}, beforeSideEffect(ErrManifestRejected)
	}
	if err := validateManifest(manifest, entries, verifier.limits); err != nil {
		cleanup()
		return VerifiedPackage{}, beforeSideEffect(err)
	}
	manifestDigest := sha256.Sum256(canonical)
	contentDigest := logicalContentDigest(entries)
	if err := verifyPublisherSignature(ctx, verifier.publishers, manifest, signature, manifestDigest, contentDigest); err != nil {
		cleanup()
		return VerifiedPackage{}, beforeSideEffect(err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return VerifiedPackage{}, ErrArtifactUnavailable
	}
	return VerifiedPackage{
		Manifest: manifest, PackageSHA256: hex.EncodeToString(packageHash.Sum(nil)),
		ManifestDigest: hex.EncodeToString(manifestDigest[:]), ContentDigest: hex.EncodeToString(contentDigest[:]),
		SizeBytes: declaredBytes, lifecycle: &verifiedPackageLifecycle{path: temporaryPath},
	}, nil
}

func (verifier *StreamingPackageVerifier) inspectArchive(ctx context.Context, packageFile *os.File) ([]byte, []byte, []verifiedEntry, error) {
	var fixedHeader [10]byte
	if _, err := io.ReadFull(packageFile, fixedHeader[:]); err != nil || fixedHeader[0] != 0x1f || fixedHeader[1] != 0x8b || fixedHeader[2] != 8 || fixedHeader[3] != 0 {
		return nil, nil, nil, ErrManifestRejected
	}
	if _, err := packageFile.Seek(0, io.SeekStart); err != nil {
		return nil, nil, nil, ErrArtifactUnavailable
	}
	buffered := bufio.NewReader(packageFile)
	gzipReader, err := gzip.NewReader(buffered)
	if err != nil {
		return nil, nil, nil, ErrManifestRejected
	}
	gzipReader.Multistream(false)
	defer gzipReader.Close()
	expandedStream := &io.LimitedReader{R: gzipReader, N: verifier.limits.MaxExpandedBytes + 1}
	tarReader := tar.NewReader(expandedStream)
	seen := make(map[string]struct{})
	entries := make([]verifiedEntry, 0)
	var manifestBytes, signature []byte
	var expanded int64
	for count := 0; ; count++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, err
		}
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil || header == nil || count >= verifier.limits.MaxFiles {
			if expandedStream.N == 0 {
				return nil, nil, nil, ErrPackageTooLarge
			}
			if count >= verifier.limits.MaxFiles {
				return nil, nil, nil, ErrPackageTooLarge
			}
			return nil, nil, nil, ErrManifestRejected
		}
		name, pathErr := canonicalArchivePath(header.Name, header.Typeflag == tar.TypeDir)
		if pathErr != nil {
			return nil, nil, nil, ErrManifestRejected
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, nil, nil, ErrManifestRejected
		}
		seen[name] = struct{}{}
		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 {
				return nil, nil, nil, ErrManifestRejected
			}
			continue
		case tar.TypeReg, tar.TypeRegA:
		default:
			return nil, nil, nil, ErrManifestRejected
		}
		if forbiddenPackagePath(name) {
			return nil, nil, nil, ErrManifestRejected
		}
		if header.Size < 0 || header.Size > verifier.limits.MaxFileBytes {
			return nil, nil, nil, ErrPackageTooLarge
		}
		if expanded > verifier.limits.MaxExpandedBytes-header.Size {
			return nil, nil, nil, ErrPackageTooLarge
		}
		expanded += header.Size
		if name == manifestPath && header.Size > verifier.limits.MaxManifestBytes {
			return nil, nil, nil, ErrPackageTooLarge
		}
		var capture bytes.Buffer
		hash := sha256.New()
		writer := io.Writer(hash)
		if name == manifestPath || name == signaturePath {
			writer = io.MultiWriter(hash, &capture)
		}
		copied, copyErr := copyNWithContext(ctx, writer, tarReader, header.Size)
		if copyErr != nil || copied != header.Size {
			if expandedStream.N == 0 {
				return nil, nil, nil, ErrPackageTooLarge
			}
			return nil, nil, nil, ErrManifestRejected
		}
		var digest [sha256.Size]byte
		copy(digest[:], hash.Sum(nil))
		entries = append(entries, verifiedEntry{path: name, size: header.Size, digest: digest})
		switch name {
		case manifestPath:
			manifestBytes = append([]byte(nil), capture.Bytes()...)
		case signaturePath:
			signature = append([]byte(nil), capture.Bytes()...)
		}
	}
	if len(manifestBytes) == 0 || len(signature) != 64 {
		return nil, nil, nil, ErrManifestRejected
	}
	trailing, drainErr := copyWithContext(ctx, io.Discard, expandedStream)
	if expandedStream.N == 0 {
		return nil, nil, nil, ErrPackageTooLarge
	}
	if drainErr != nil || trailing != 0 {
		return nil, nil, nil, ErrManifestRejected
	}
	if _, peekErr := buffered.Peek(1); !errors.Is(peekErr, io.EOF) {
		return nil, nil, nil, ErrManifestRejected
	}
	return manifestBytes, signature, entries, nil
}

func canonicalArchivePath(value string, directory bool) (string, error) {
	if value == "" || strings.ContainsAny(value, "\\\x00") || path.IsAbs(value) || filepath.IsAbs(value) || filepath.VolumeName(value) != "" {
		return "", ErrManifestRejected
	}
	trimmed := value
	if directory {
		trimmed = strings.TrimSuffix(trimmed, "/")
	}
	if trimmed == "" || path.Clean(trimmed) != trimmed || trimmed == "plugin-package" || !strings.HasPrefix(trimmed, "plugin-package/") {
		return "", ErrManifestRejected
	}
	for _, part := range strings.Split(trimmed, "/") {
		if part == "" || part == "." || part == ".." {
			return "", ErrManifestRejected
		}
	}
	return trimmed, nil
}

func forbiddenPackagePath(value string) bool {
	lower := strings.ToLower(value)
	for _, part := range strings.Split(lower, "/") {
		if part == "scripts" || part == "hooks" || part == "script" || part == "hook" {
			return true
		}
	}
	for _, suffix := range []string{".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func decodeCanonicalManifest(encoded []byte) (Manifest, []byte, error) {
	var generic any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&generic); err != nil || generic == nil || containsSensitiveManifestKey(generic) {
		return Manifest{}, nil, ErrManifestRejected
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Manifest{}, nil, ErrManifestRejected
	}
	canonical, err := json.Marshal(generic)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Manifest{}, nil, ErrManifestRejected
	}
	strict := json.NewDecoder(bytes.NewReader(encoded))
	strict.DisallowUnknownFields()
	var manifest Manifest
	if err := strict.Decode(&manifest); err != nil || ensureJSONEOF(strict) != nil {
		return Manifest{}, nil, ErrManifestRejected
	}
	return manifest, canonical, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrManifestRejected
	}
	return nil
}

func containsSensitiveManifestKey(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.Map(func(character rune) rune {
				if unicode.IsLetter(character) || unicode.IsDigit(character) {
					return unicode.ToLower(character)
				}
				return -1
			}, key)
			for _, marker := range []string{"password", "passwd", "credential", "secret", "privatekey", "accesstoken", "refreshtoken", "downloadurl", "externaldownload", "script", "hook"} {
				if strings.Contains(normalized, marker) {
					return true
				}
			}
			if containsSensitiveManifestKey(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsSensitiveManifestKey(child) {
				return true
			}
		}
	}
	return false
}

var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validateManifest(manifest Manifest, entries []verifiedEntry, limits PackageLimits) error {
	if !identifierPattern.MatchString(manifest.PluginID) || !identifierPattern.MatchString(manifest.DatabaseFamily) || !identifierPattern.MatchString(manifest.PublisherID) || !identifierPattern.MatchString(manifest.SigningKeyID) || !canonicalText(manifest.Version, 64) || !canonicalText(manifest.ProtocolVersion, 32) || !canonicalText(manifest.MinimumAgentProtocolVersion, 32) || !canonicalText(manifest.MaximumAgentProtocolVersion, 32) || !canonicalText(manifest.DatabaseVersionRange, 128) || manifest.MetricTemplateSchemaVersion < 1 || manifest.MetricTemplateSchemaVersion > 65535 || len(manifest.Binaries) == 0 || len(manifest.Binaries) > 16 || len(manifest.Files) == 0 || len(manifest.Files) > limits.MaxFiles || !uniqueCanonicalIdentifiers(manifest.SupportedVariants, 16) || !uniqueCanonicalIdentifiers(manifest.Capabilities, 64) {
		return ErrManifestRejected
	}
	actual := make(map[string]verifiedEntry, len(entries))
	for _, entry := range entries {
		actual[entry.path] = entry
	}
	declared := make(map[string]ManifestFile, len(manifest.Files))
	for _, file := range manifest.Files {
		name, err := canonicalArchivePath(file.Path, false)
		if err != nil || name == manifestPath || name == signaturePath || forbiddenPackagePath(name) || !digestPattern.MatchString(file.SHA256) || file.SizeBytes <= 0 || file.SizeBytes > limits.MaxFileBytes {
			return ErrManifestRejected
		}
		if _, duplicate := declared[name]; duplicate {
			return ErrManifestRejected
		}
		entry, ok := actual[name]
		if !ok || entry.size != file.SizeBytes || hex.EncodeToString(entry.digest[:]) != file.SHA256 {
			return ErrManifestRejected
		}
		declared[name] = file
	}
	for _, entry := range entries {
		if entry.path == manifestPath || entry.path == signaturePath {
			continue
		}
		if _, ok := declared[entry.path]; !ok {
			return ErrManifestRejected
		}
	}
	hasSupportedPlatform := false
	seenPlatforms := make(map[string]struct{}, len(manifest.Binaries))
	for _, binary := range manifest.Binaries {
		platform := binary.OperatingSystem + "-" + binary.Architecture
		if _, duplicate := seenPlatforms[platform]; duplicate {
			return ErrManifestRejected
		}
		seenPlatforms[platform] = struct{}{}
		if binary.OperatingSystem != "linux" || binary.Architecture != "amd64" && binary.Architecture != "arm64" {
			continue
		}
		hasSupportedPlatform = true
		if !strings.HasPrefix(binary.Path, "plugin-package/bin/"+platform+"/") || !digestPattern.MatchString(binary.SHA256) || binary.SizeBytes <= 0 {
			return ErrManifestRejected
		}
		file, ok := declared[binary.Path]
		if !ok || file.SHA256 != binary.SHA256 || file.SizeBytes != binary.SizeBytes {
			return ErrManifestRejected
		}
	}
	if !hasSupportedPlatform {
		return ErrPlatformMismatch
	}
	return nil
}

func canonicalText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\r\n\t\x00")
}

func uniqueCanonicalIdentifiers(values []string, maximum int) bool {
	if len(values) == 0 || len(values) > maximum {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !identifierPattern.MatchString(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func logicalContentDigest(entries []verifiedEntry) [sha256.Size]byte {
	content := make([]verifiedEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.path != signaturePath {
			content = append(content, entry)
		}
	}
	sort.Slice(content, func(left, right int) bool { return content[left].path < content[right].path })
	hash := sha256.New()
	_, _ = io.WriteString(hash, "dbpilot-plugin-content-v1\n")
	for _, entry := range content {
		writeLengthPrefixedValue(hash, entry.path)
		writeLengthPrefixedValue(hash, strconv.FormatInt(entry.size, 10))
		writeLengthPrefixedValue(hash, hex.EncodeToString(entry.digest[:]))
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func writeLengthPrefixedValue(writer io.Writer, value string) {
	_, _ = io.WriteString(writer, strconv.Itoa(len(value)))
	_, _ = io.WriteString(writer, ":")
	_, _ = io.WriteString(writer, value)
}

func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 32<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			written, writeErr := destination.Write(buffer[:read])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != read {
				return total, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
		if read == 0 {
			return total, io.ErrNoProgress
		}
	}
}

func copyNWithContext(ctx context.Context, destination io.Writer, source io.Reader, count int64) (int64, error) {
	return copyWithContext(ctx, destination, io.LimitReader(source, count))
}

func beforeSideEffect(err error) error {
	return fmt.Errorf("%w: %w", ErrBeforeSideEffect, err)
}

var _ PackageVerifier = (*StreamingPackageVerifier)(nil)
