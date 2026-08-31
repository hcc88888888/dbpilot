package pluginsupervisor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHTTPSArtifactDownloaderAcceptsOnlyBoundedSameOriginLease(t *testing.T) {
	payload := []byte("signed plugin package")
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "lease-secret", request.Header.Get("X-DBPilot-Artifact-Lease"))
		writer.Header().Set("Content-Length", "21")
		_, _ = writer.Write(payload)
	}))
	defer server.Close()
	downloader, err := NewHTTPSArtifactDownloader(ArtifactDownloadConfig{Client: server.Client(), Origin: server.URL, MaximumBytes: 1024, Timeout: time.Second})
	require.NoError(t, err)

	artifact, err := downloader.Download(context.Background(), ArtifactLease{LeaseID: "lease-1", AssignmentID: "assignment-1", ArtifactID: "artifact-1", OperationRevision: 1, ExpiresAt: time.Now().Add(time.Minute), DownloadURL: server.URL + "/api/v1/agent/plugin-artifacts/lease-1", RequestHeaders: map[string]string{"X-DBPilot-Artifact-Lease": "lease-secret"}})
	require.NoError(t, err)
	require.Equal(t, int64(len(payload)), artifact.Size)
	body, err := io.ReadAll(artifact.Body)
	require.NoError(t, err)
	require.NoError(t, artifact.Body.Close())
	require.Equal(t, payload, body)
}

func TestHTTPSArtifactDownloaderRejectsRedirectOriginExpiryAndOversizeWithoutFollowing(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/redirect":
			http.Redirect(writer, request, target.URL, http.StatusFound)
		case "/large":
			writer.Header().Set("Content-Length", "2048")
			writer.WriteHeader(http.StatusOK)
		default:
			writer.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	downloader, err := NewHTTPSArtifactDownloader(ArtifactDownloadConfig{Client: server.Client(), Origin: server.URL, MaximumBytes: 1024, Timeout: time.Second})
	require.NoError(t, err)

	base := ArtifactLease{LeaseID: "lease-1", AssignmentID: "assignment-1", ArtifactID: "artifact-1", OperationRevision: 1, ExpiresAt: time.Now().Add(time.Minute), DownloadURL: server.URL + "/redirect"}
	_, err = downloader.Download(context.Background(), base)
	require.ErrorIs(t, err, ErrArtifactDownload)
	require.Zero(t, redirected.Load())

	offOrigin := base
	offOrigin.DownloadURL = target.URL + "/artifact"
	_, err = downloader.Download(context.Background(), offOrigin)
	require.ErrorIs(t, err, ErrArtifactLease)

	expired := base
	expired.ExpiresAt = time.Now().Add(-time.Second)
	_, err = downloader.Download(context.Background(), expired)
	require.ErrorIs(t, err, ErrArtifactLease)

	large := base
	large.DownloadURL = server.URL + "/large"
	_, err = downloader.Download(context.Background(), large)
	require.ErrorIs(t, err, ErrArtifactDownload)
}
