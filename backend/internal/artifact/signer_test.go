package artifact

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/database"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestHMACDownloadSignerBindsArtifactScopeAndExpiry(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	signer, err := NewHMACDownloadSigner("https://control.example/api/v1/artifacts", "secret://control/download", database.StaticSecretResolver{"secret://control/download": []byte("0123456789abcdef0123456789abcdef")})
	require.NoError(t, err)
	signer.now = func() time.Time { return now }
	artifact := Artifact{ID: "artifact-1", Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}}

	signed, err := signer.Sign(context.Background(), artifact, now.Add(time.Minute))
	require.NoError(t, err)
	claims, err := signer.Verify(context.Background(), signed)
	require.NoError(t, err)
	require.Equal(t, artifact.ID, claims.ArtifactID)
	require.Equal(t, artifact.Scope, claims.Scope)
	require.Equal(t, now.Add(time.Minute), claims.ExpiresAt)

	for name, mutate := range map[string]func(*url.URL){
		"artifact ID": func(value *url.URL) { value.Path = "/api/v1/artifacts/artifact-2" },
		"scope": func(value *url.URL) {
			query := value.Query()
			query.Set("project_id", "project-2")
			value.RawQuery = query.Encode()
		},
		"expiry": func(value *url.URL) {
			query := value.Query()
			query.Set("expires", "9999999999")
			value.RawQuery = query.Encode()
		},
	} {
		t.Run(name, func(t *testing.T) {
			value, parseErr := url.Parse(signed)
			require.NoError(t, parseErr)
			mutate(value)
			_, verifyErr := signer.Verify(context.Background(), value.String())
			require.ErrorIs(t, verifyErr, ErrInvalidSignature)
		})
	}
}

func TestHMACDownloadSignerRejectsExpiredDescriptor(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	signer, err := NewHMACDownloadSigner("/api/v1/artifacts", "secret://control/download", database.StaticSecretResolver{"secret://control/download": []byte("0123456789abcdef0123456789abcdef")})
	require.NoError(t, err)
	signer.now = func() time.Time { return now }
	signed, err := signer.Sign(context.Background(), Artifact{ID: "artifact-1", Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}}, now.Add(time.Minute))
	require.NoError(t, err)
	signer.now = func() time.Time { return now.Add(2 * time.Minute) }

	_, err = signer.Verify(context.Background(), signed)
	require.ErrorIs(t, err, ErrExpired)
}

func TestSpecialArtifactIDRoundTripsThroughOneBase64URLPathSegment(t *testing.T) {
	signer, err := NewHMACDownloadSigner("https://control.example/api/v1/artifact-downloads", "secret://control/download", database.StaticSecretResolver{"secret://control/download": []byte("0123456789abcdef0123456789abcdef")})
	require.NoError(t, err)
	now := time.Now().UTC()
	id := "artifact/with space?#%中文"
	signed, err := signer.Sign(context.Background(), Artifact{ID: id, Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}}, now.Add(time.Minute))
	require.NoError(t, err)
	parsed, err := url.Parse(signed)
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(parsed.EscapedPath(), "/"+base64.RawURLEncoding.EncodeToString([]byte(id))))

	claims, err := signer.Verify(context.Background(), signed)
	require.NoError(t, err)
	require.Equal(t, id, claims.ArtifactID)
}
