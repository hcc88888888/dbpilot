package artifact

import (
	"errors"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

const MaximumDownloadTTL = 5 * time.Minute

var (
	ErrNotFound                 = errors.New("artifact not found")
	ErrExpired                  = errors.New("artifact expired")
	ErrInvalid                  = errors.New("invalid artifact request")
	ErrInvalidSignature         = errors.New("invalid artifact download signature")
	ErrBeforeDownloadSideEffect = errors.New("artifact download failed before signer invocation")
)

type ResourceReference struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
}

type Artifact struct {
	ID               string              `json:"id"`
	Scope            platformscope.Scope `json:"scope"`
	Kind             string              `json:"kind"`
	ContentType      string              `json:"content_type"`
	SizeBytes        int64               `json:"size_bytes"`
	Checksum         string              `json:"checksum"`
	SourceResource   ResourceReference   `json:"source_resource,omitempty"`
	JobID            string              `json:"job_id,omitempty"`
	CreatedBy        string              `json:"created_by,omitempty"`
	CreatedAt        time.Time           `json:"created_at"`
	ExpiresAt        *time.Time          `json:"expires_at,omitempty"`
	StorageReference string              `json:"-"`
}

type Download struct {
	URL       string            `json:"url"`
	ExpiresAt time.Time         `json:"expires_at"`
	Headers   map[string]string `json:"headers,omitempty"`
}

type DownloadClaims struct {
	ArtifactID string
	Scope      platformscope.Scope
	ExpiresAt  time.Time
}
