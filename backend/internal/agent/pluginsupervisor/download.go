package pluginsupervisor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ArtifactDownloadConfig struct {
	Client       *http.Client
	Origin       string
	MaximumBytes int64
	Timeout      time.Duration
	Now          func() time.Time
}

type HTTPSArtifactDownloader struct {
	client       *http.Client
	origin       *url.URL
	maximumBytes int64
	timeout      time.Duration
	now          func() time.Time
}

func NewHTTPSArtifactDownloader(config ArtifactDownloadConfig) (*HTTPSArtifactDownloader, error) {
	if config.Client == nil || config.MaximumBytes <= 0 || config.MaximumBytes > 256<<20 || config.Timeout <= 0 || config.Timeout > 5*time.Minute {
		return nil, ErrArtifactLease
	}
	origin, err := url.Parse(config.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, ErrArtifactLease
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 0
	if config.Now == nil {
		config.Now = time.Now
	}
	return &HTTPSArtifactDownloader{client: &client, origin: origin, maximumBytes: config.MaximumBytes, timeout: config.Timeout, now: config.Now}, nil
}

func (downloader *HTTPSArtifactDownloader) Download(ctx context.Context, lease ArtifactLease) (DownloadedArtifact, error) {
	if downloader == nil || ctx == nil || ctx.Err() != nil || !resourceIdentifier.MatchString(lease.LeaseID) || !resourceIdentifier.MatchString(lease.AssignmentID) || !resourceIdentifier.MatchString(lease.ArtifactID) || lease.OperationRevision == 0 || !lease.ExpiresAt.After(downloader.now()) || len(lease.RequestHeaders) > 8 {
		return DownloadedArtifact{}, ErrArtifactLease
	}
	target, err := url.Parse(lease.DownloadURL)
	if err != nil || target.Scheme != downloader.origin.Scheme || !strings.EqualFold(target.Host, downloader.origin.Host) || target.User != nil || target.Fragment != "" || target.RawQuery != "" || target.Path == "" {
		return DownloadedArtifact{}, ErrArtifactLease
	}
	requestContext, cancel := context.WithTimeout(ctx, downloader.timeout)
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, target.String(), nil)
	if err != nil {
		cancel()
		return DownloadedArtifact{}, ErrArtifactLease
	}
	for name, value := range lease.RequestHeaders {
		canonical := http.CanonicalHeaderKey(name)
		if canonical != "Authorization" && canonical != "X-Dbpilot-Artifact-Lease" || value == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			cancel()
			return DownloadedArtifact{}, ErrArtifactLease
		}
		request.Header.Set(canonical, value)
	}
	request.Header.Set("Accept", "application/gzip")
	response, err := downloader.client.Do(request)
	if err != nil {
		cancel()
		return DownloadedArtifact{}, ErrArtifactDownload
	}
	if response.StatusCode != http.StatusOK || response.ContentLength <= 0 || response.ContentLength > downloader.maximumBytes || response.Header.Get("Location") != "" {
		_ = response.Body.Close()
		cancel()
		return DownloadedArtifact{}, ErrArtifactDownload
	}
	return DownloadedArtifact{Body: &leaseBody{ReadCloser: response.Body, remaining: response.ContentLength + 1, cancel: cancel}, Size: response.ContentLength}, nil
}

type leaseBody struct {
	io.ReadCloser
	remaining int64
	cancel    context.CancelFunc
}

func (body *leaseBody) Read(buffer []byte) (int, error) {
	if body.remaining <= 0 {
		return 0, errors.New("artifact response exceeded declared length")
	}
	if int64(len(buffer)) > body.remaining {
		buffer = buffer[:body.remaining]
	}
	read, err := body.ReadCloser.Read(buffer)
	body.remaining -= int64(read)
	return read, err
}

func (body *leaseBody) Close() error {
	err := body.ReadCloser.Close()
	body.cancel()
	return err
}

var _ ArtifactDownloader = (*HTTPSArtifactDownloader)(nil)
