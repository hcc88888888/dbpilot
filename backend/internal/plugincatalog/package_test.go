package plugincatalog

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
	"fmt"
	"io"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPackageVerifierRejectsUnsafeTarHeadersBeforeReadingPayloads(t *testing.T) {
	// Break caught: accepting any of these headers lets an uploaded package
	// escape its logical root or smuggle link-based filesystem references.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	valid := newSignedPackageFixture(t, "publisher-1", "key-1", private, nil)

	tests := []struct {
		name   string
		mutate func([]tarFixtureEntry) []tarFixtureEntry
		err    error
	}{
		{name: "absolute unix path", mutate: renameBinaryEntry("/plugin-package/bin/linux-amd64/dbpilot-plugin-mysql"), err: ErrManifestRejected},
		{name: "absolute windows path", mutate: renameBinaryEntry(`C:/plugin-package/bin/linux-amd64/dbpilot-plugin-mysql`), err: ErrManifestRejected},
		{name: "parent traversal", mutate: renameBinaryEntry("plugin-package/bin/../escape"), err: ErrManifestRejected},
		{name: "duplicate entry", mutate: func(entries []tarFixtureEntry) []tarFixtureEntry {
			for _, entry := range entries {
				if entry.Name == testBinaryPath {
					return append(entries, entry)
				}
			}
			return entries
		}, err: ErrManifestRejected},
		{name: "symlink", mutate: replaceBinaryType(tar.TypeSymlink, "../../outside"), err: ErrManifestRejected},
		{name: "hardlink", mutate: replaceBinaryType(tar.TypeLink, "../../outside"), err: ErrManifestRejected},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive := writeTarGzip(t, test.mutate(cloneTarEntries(valid.Entries)))
			_, err := newTestPackageVerifier(t, public, testPackageLimits()).Verify(context.Background(), bytes.NewReader(archive), int64(len(archive)))
			require.ErrorIs(t, err, test.err)
		})
	}
}

func TestPackageVerifierEnforcesCompressedFileCountAndExpandedBounds(t *testing.T) {
	// Break caught: every limit must be enforced while streaming, before an
	// attacker can turn a small gzip into unbounded disk or CPU consumption.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	largeBody := bytes.Repeat([]byte("x"), 4096)
	fixture := newSignedPackageFixture(t, "publisher-1", "key-1", private, func(manifest map[string]any, entries *[]tarFixtureEntry) {
		path := "plugin-package/schemas/large.json"
		appendManifestFile(manifest, path, largeBody)
		*entries = append(*entries, tarFixtureEntry{Name: path, Body: largeBody, Mode: 0o400})
	})

	tests := []struct {
		name          string
		limits        PackageLimits
		declaredBytes int64
	}{
		{name: "compressed upload", limits: func() PackageLimits {
			value := testPackageLimits()
			value.MaxCompressedBytes = int64(len(fixture.Archive) - 1)
			return value
		}(), declaredBytes: int64(len(fixture.Archive))},
		{name: "single file", limits: func() PackageLimits {
			value := testPackageLimits()
			value.MaxFileBytes = 2048
			value.MaxManifestBytes = 2048
			return value
		}(), declaredBytes: int64(len(fixture.Archive))},
		{name: "entry count", limits: func() PackageLimits { value := testPackageLimits(); value.MaxFiles = 3; return value }(), declaredBytes: int64(len(fixture.Archive))},
		{name: "expanded bytes", limits: func() PackageLimits { value := testPackageLimits(); value.MaxExpandedBytes = 2048; return value }(), declaredBytes: int64(len(fixture.Archive))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := newTestPackageVerifier(t, public, test.limits).Verify(context.Background(), bytes.NewReader(fixture.Archive), test.declaredBytes)
			require.ErrorIs(t, err, ErrPackageTooLarge)
		})
	}
}

func TestPackageVerifierBoundsDecompressionAfterTarEndMarkers(t *testing.T) {
	// Break caught: a gzip bomb can place an unbounded compressed suffix after
	// the tar end markers unless the decompressor itself is limited.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	fixture := newSignedPackageFixture(t, "publisher-1", "key-1", private, nil)
	archive := writeTarGzipWithTrailing(t, fixture.Entries, bytes.Repeat([]byte{0}, 1<<20))
	limits := testPackageLimits()
	limits.MaxExpandedBytes = 32 << 10

	_, err = newTestPackageVerifier(t, public, limits).Verify(context.Background(), bytes.NewReader(archive), int64(len(archive)))
	require.ErrorIs(t, err, ErrPackageTooLarge)
}

func TestPackageVerifierRejectsOptionalGzipHeadersBeforeAllocation(t *testing.T) {
	// Break caught: unbounded FNAME/FCOMMENT fields are parsed by compress/gzip
	// before tar limits apply and can consume upload-sized memory.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	fixture := newSignedPackageFixture(t, "publisher-1", "key-1", private, nil)
	archive := writeTarGzipWithOptions(t, fixture.Entries, nil, "attacker-controlled-name")

	_, err = newTestPackageVerifier(t, public, testPackageLimits()).Verify(context.Background(), bytes.NewReader(archive), int64(len(archive)))
	require.ErrorIs(t, err, ErrManifestRejected)
}

func TestPackageVerifierRejectsManifestAndExecutableMismatches(t *testing.T) {
	// Break caught: the verifier must derive hashes from streamed entry bytes,
	// never from manifest or caller claims.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name    string
		fixture signedPackageFixture
		mutate  func([]tarFixtureEntry) []tarFixtureEntry
	}{
		{
			name:    "manifest file digest mismatch",
			fixture: newSignedPackageFixture(t, "publisher-1", "key-1", private, nil),
			mutate: func(entries []tarFixtureEntry) []tarFixtureEntry {
				for index := range entries {
					if entries[index].Name == testBinaryPath {
						entries[index].Body = []byte("tampered executable")
					}
				}
				return entries
			},
		},
		{
			name: "missing binary",
			fixture: newSignedPackageFixture(t, "publisher-1", "key-1", private, func(_ map[string]any, entries *[]tarFixtureEntry) {
				filtered := (*entries)[:0]
				for _, entry := range *entries {
					if entry.Name != testBinaryPath {
						filtered = append(filtered, entry)
					}
				}
				*entries = filtered
			}),
			mutate: func(entries []tarFixtureEntry) []tarFixtureEntry { return entries },
		},
		{
			name: "executable digest mismatch",
			fixture: newSignedPackageFixture(t, "publisher-1", "key-1", private, func(manifest map[string]any, _ *[]tarFixtureEntry) {
				binaries := manifest["binaries"].([]any)
				binaries[0].(map[string]any)["sha256"] = stringsOfZeros(64)
			}),
			mutate: func(entries []tarFixtureEntry) []tarFixtureEntry { return entries },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive := writeTarGzip(t, test.mutate(cloneTarEntries(test.fixture.Entries)))
			_, err := newTestPackageVerifier(t, public, testPackageLimits()).Verify(context.Background(), bytes.NewReader(archive), int64(len(archive)))
			require.ErrorIs(t, err, ErrManifestRejected)
		})
	}
}

func TestPackageVerifierRejectsWrongPlatformScriptsHooksAndSecretFields(t *testing.T) {
	// Break caught: a valid publisher signature must not authorize packages the
	// Server cannot safely deploy, including executable hooks or secret data.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name    string
		fixture signedPackageFixture
		want    error
	}{
		{
			name: "wrong platform",
			fixture: newSignedPackageFixture(t, "publisher-1", "key-1", private, func(manifest map[string]any, entries *[]tarFixtureEntry) {
				windowsPath := "plugin-package/bin/windows-amd64/dbpilot-plugin-mysql.exe"
				for index := range *entries {
					if (*entries)[index].Name == testBinaryPath {
						(*entries)[index].Name = windowsPath
					}
				}
				files := manifest["files"].([]any)
				files[0].(map[string]any)["path"] = windowsPath
				binary := manifest["binaries"].([]any)[0].(map[string]any)
				binary["operating_system"] = "windows"
				binary["path"] = windowsPath
			}),
			want: ErrPlatformMismatch,
		},
		{
			name: "script payload",
			fixture: newSignedPackageFixture(t, "publisher-1", "key-1", private, func(manifest map[string]any, entries *[]tarFixtureEntry) {
				path, body := "plugin-package/scripts/install.sh", []byte("#!/bin/sh\n")
				appendManifestFile(manifest, path, body)
				*entries = append(*entries, tarFixtureEntry{Name: path, Body: body, Mode: 0o500})
			}),
			want: ErrManifestRejected,
		},
		{
			name: "install hook declaration",
			fixture: newSignedPackageFixture(t, "publisher-1", "key-1", private, func(manifest map[string]any, _ *[]tarFixtureEntry) {
				manifest["post_install_hook"] = "plugin-package/bin/linux-amd64/dbpilot-plugin-mysql --install"
			}),
			want: ErrManifestRejected,
		},
		{
			name: "secret-looking field",
			fixture: newSignedPackageFixture(t, "publisher-1", "key-1", private, func(manifest map[string]any, _ *[]tarFixtureEntry) {
				manifest["database_password"] = "do-not-store"
			}),
			want: ErrManifestRejected,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := newTestPackageVerifier(t, public, testPackageLimits()).Verify(context.Background(), bytes.NewReader(test.fixture.Archive), int64(len(test.fixture.Archive)))
			require.ErrorIs(t, err, test.want)
		})
	}
}

func TestPackageVerifierAcceptsCanonicalSignedPackageAndDerivesDigests(t *testing.T) {
	// Break caught: returning caller/manifest claims instead of hashes derived
	// from the actual archive would publish the wrong immutable Artifact.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	fixture := newSignedPackageFixture(t, "publisher-1", "key-1", private, nil)
	wantPackageDigest := sha256.Sum256(fixture.Archive)
	wantManifestDigest := sha256.Sum256(fixture.Manifest)

	verified, err := newTestPackageVerifier(t, public, testPackageLimits()).Verify(context.Background(), bytes.NewReader(fixture.Archive), int64(len(fixture.Archive)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, verified.Close()) })
	require.Equal(t, hex.EncodeToString(wantPackageDigest[:]), verified.PackageSHA256)
	require.Equal(t, hex.EncodeToString(wantManifestDigest[:]), verified.ManifestDigest)
	require.Equal(t, int64(len(fixture.Archive)), verified.SizeBytes)
	require.Equal(t, "mysql", verified.Manifest.PluginID)
	require.Equal(t, "publisher-1", verified.Manifest.PublisherID)
	reader, err := verified.Open()
	require.NoError(t, err)
	defer reader.Close()
	stored, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, fixture.Archive, stored)
}

const testBinaryPath = "plugin-package/bin/linux-amd64/dbpilot-plugin-mysql"

type testPublisherStore map[string]ed25519.PublicKey

func (store testPublisherStore) PublicKey(_ context.Context, publisherID, keyID string) (ed25519.PublicKey, error) {
	key, ok := store[publisherID+"\x00"+keyID]
	if !ok {
		return nil, ErrUnknownPublisher
	}
	return append(ed25519.PublicKey(nil), key...), nil
}

func newTestPackageVerifier(t *testing.T, public ed25519.PublicKey, limits PackageLimits) *StreamingPackageVerifier {
	t.Helper()
	verifier, err := NewStreamingPackageVerifier(PackageVerifierConfig{
		Publishers:         testPublisherStore{"publisher-1\x00key-1": public},
		TemporaryDirectory: t.TempDir(),
		Limits:             limits,
	})
	require.NoError(t, err)
	return verifier
}

func testPackageLimits() PackageLimits {
	return PackageLimits{
		MaxCompressedBytes: 2 << 20,
		MaxExpandedBytes:   4 << 20,
		MaxFileBytes:       2 << 20,
		MaxFiles:           64,
		MaxManifestBytes:   1 << 20,
	}
}

type tarFixtureEntry struct {
	Name     string
	Body     []byte
	Typeflag byte
	Linkname string
	Mode     int64
}

type signedPackageFixture struct {
	Archive  []byte
	Entries  []tarFixtureEntry
	Manifest []byte
}

func newSignedPackageFixture(t *testing.T, publisherID, keyID string, private ed25519.PrivateKey, mutate func(map[string]any, *[]tarFixtureEntry)) signedPackageFixture {
	t.Helper()
	binary := []byte("\x7fELF dbpilot mysql plugin\n")
	binaryDigest := sha256.Sum256(binary)
	manifest := map[string]any{
		"plugin_id":                      "mysql",
		"database_family":                "mysql",
		"version":                        "1.0.0",
		"protocol_version":               "v1",
		"publisher_id":                   publisherID,
		"signing_key_id":                 keyID,
		"minimum_agent_protocol_version": "v1",
		"maximum_agent_protocol_version": "v1",
		"supported_variants":             []any{"mysql"},
		"database_version_range":         ">=8.0.0 <9.0.0",
		"capabilities":                   []any{"metrics.collect"},
		"metric_template_schema_version": float64(1),
		"binaries": []any{map[string]any{
			"operating_system": "linux",
			"architecture":     "amd64",
			"path":             testBinaryPath,
			"sha256":           hex.EncodeToString(binaryDigest[:]),
			"size_bytes":       float64(len(binary)),
		}},
		"files": []any{map[string]any{
			"path":       testBinaryPath,
			"sha256":     hex.EncodeToString(binaryDigest[:]),
			"size_bytes": float64(len(binary)),
		}},
	}
	entries := []tarFixtureEntry{{Name: testBinaryPath, Body: binary, Mode: 0o500}}
	if mutate != nil {
		mutate(manifest, &entries)
	}
	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)
	entries = append([]tarFixtureEntry{{Name: "plugin-package/manifest.json", Body: manifestBytes, Mode: 0o400}}, entries...)
	contentDigest := independentLogicalContentDigest(entries)
	manifestDigest := sha256.Sum256(manifestBytes)
	signature := ed25519.Sign(private, independentSignatureMessage(manifestDigest, contentDigest))
	entries = append(entries, tarFixtureEntry{Name: "plugin-package/SIGNATURE.ed25519", Body: signature, Mode: 0o400})
	return signedPackageFixture{Archive: writeTarGzip(t, entries), Entries: entries, Manifest: manifestBytes}
}

func appendManifestFile(manifest map[string]any, path string, body []byte) {
	digest := sha256.Sum256(body)
	manifest["files"] = append(manifest["files"].([]any), map[string]any{
		"path":       path,
		"sha256":     hex.EncodeToString(digest[:]),
		"size_bytes": float64(len(body)),
	})
}

func independentLogicalContentDigest(entries []tarFixtureEntry) [sha256.Size]byte {
	regular := make([]tarFixtureEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Name != "plugin-package/SIGNATURE.ed25519" && (entry.Typeflag == 0 || entry.Typeflag == tar.TypeReg) {
			regular = append(regular, entry)
		}
	}
	sort.Slice(regular, func(left, right int) bool { return regular[left].Name < regular[right].Name })
	hash := sha256.New()
	_, _ = io.WriteString(hash, "dbpilot-plugin-content-v1\n")
	for _, entry := range regular {
		digest := sha256.Sum256(entry.Body)
		writeLengthPrefixed(hash, entry.Name)
		writeLengthPrefixed(hash, strconv.FormatInt(int64(len(entry.Body)), 10))
		writeLengthPrefixed(hash, hex.EncodeToString(digest[:]))
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func independentSignatureMessage(manifestDigest, contentDigest [sha256.Size]byte) []byte {
	return []byte("dbpilot-plugin-signature-v1\nmanifest-sha256:" + hex.EncodeToString(manifestDigest[:]) + "\ncontent-sha256:" + hex.EncodeToString(contentDigest[:]) + "\n")
}

func writeLengthPrefixed(writer io.Writer, value string) {
	_, _ = io.WriteString(writer, strconv.Itoa(len(value)))
	_, _ = io.WriteString(writer, ":")
	_, _ = io.WriteString(writer, value)
}

func writeTarGzip(t *testing.T, entries []tarFixtureEntry) []byte {
	return writeTarGzipWithOptions(t, entries, nil, "")
}

func writeTarGzipWithTrailing(t *testing.T, entries []tarFixtureEntry, trailing []byte) []byte {
	return writeTarGzipWithOptions(t, entries, trailing, "")
}

func writeTarGzipWithOptions(t *testing.T, entries []tarFixtureEntry, trailing []byte, headerName string) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gzipWriter, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	require.NoError(t, err)
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	gzipWriter.Header.Name = headerName
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		typeflag := entry.Typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		mode := entry.Mode
		if mode == 0 {
			mode = 0o400
		}
		header := &tar.Header{Name: entry.Name, Mode: mode, Size: int64(len(entry.Body)), Typeflag: typeflag, Linkname: entry.Linkname, ModTime: time.Unix(0, 0).UTC()}
		if typeflag != tar.TypeReg {
			header.Size = 0
		}
		require.NoError(t, tarWriter.WriteHeader(header))
		if header.Size > 0 {
			_, err = tarWriter.Write(entry.Body)
			require.NoError(t, err)
		}
	}
	require.NoError(t, tarWriter.Close())
	if len(trailing) > 0 {
		_, err = gzipWriter.Write(trailing)
		require.NoError(t, err)
	}
	require.NoError(t, gzipWriter.Close())
	return compressed.Bytes()
}

func cloneTarEntries(entries []tarFixtureEntry) []tarFixtureEntry {
	result := make([]tarFixtureEntry, len(entries))
	for index := range entries {
		result[index] = entries[index]
		result[index].Body = append([]byte(nil), entries[index].Body...)
	}
	return result
}

func renameBinaryEntry(name string) func([]tarFixtureEntry) []tarFixtureEntry {
	return func(entries []tarFixtureEntry) []tarFixtureEntry {
		for index := range entries {
			if entries[index].Name == testBinaryPath {
				entries[index].Name = name
			}
		}
		return entries
	}
}

func replaceBinaryType(typeflag byte, linkname string) func([]tarFixtureEntry) []tarFixtureEntry {
	return func(entries []tarFixtureEntry) []tarFixtureEntry {
		for index := range entries {
			if entries[index].Name == testBinaryPath {
				entries[index].Typeflag = typeflag
				entries[index].Linkname = linkname
				entries[index].Body = nil
			}
		}
		return entries
	}
}

func stringsOfZeros(length int) string { return fmt.Sprintf("%0*d", length, 0) }
