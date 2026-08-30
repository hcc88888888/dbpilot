package plugincatalog

import (
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestPluginVersionModelUsesClosedLifecycleAndOpaqueETag(t *testing.T) {
	// Break caught: an open or mutable status vocabulary lets callers bypass
	// approval/revocation gates or forge conditional update versions.
	value := PluginVersion{
		ID: "plugin-version-1", Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"},
		PluginID: "mysql", Version: "1.0.0", Status: StatusVerified,
		ArtifactID: "plugin-package-a", PackageSHA256: stringsOfZeros(64), ManifestDigest: stringsOfZeros(64),
		PublisherID: "publisher-1", SigningKeyID: "key-1", ProtocolVersion: "v1",
		MinimumAgentProtocolVersion: "v1", MaximumAgentProtocolVersion: "v1",
		SupportedVariants: []string{"mysql"}, DatabaseVersionRange: ">=8 <9", Capabilities: []string{"metrics.collect"},
		MetricTemplateSchemaVersion: 1,
		Platforms:                   []Platform{{OperatingSystem: "linux", Architecture: "amd64", SHA256: stringsOfZeros(64), SizeBytes: 24}},
		Revision:                    7, CreatedAt: time.Date(2026, 8, 30, 3, 0, 0, 0, time.UTC),
	}

	require.NoError(t, value.Validate())
	require.Equal(t, `"7"`, value.ETag())
	require.True(t, StatusVerified.Valid())
	require.True(t, StatusAvailable.Valid())
	require.True(t, StatusRevoked.Valid())
	require.False(t, Status("publisher_says_ok").Valid())

	invalid := value
	invalid.Status = Status("publisher_says_ok")
	require.ErrorIs(t, invalid.Validate(), ErrInvalid)
}

func TestVersionFilterRejectsOutOfScopeShapedCursorAndUnboundedLimit(t *testing.T) {
	// Break caught: invalid filters must fail before repository execution rather
	// than broadening a scoped SQL query.
	tests := []VersionFilter{
		{Limit: 101},
		{Cursor: " leading-space"},
		{PluginID: "../mysql"},
		{Status: Status("not-real")},
	}
	for _, filter := range tests {
		require.ErrorIs(t, filter.Validate(), ErrInvalid)
	}
	require.NoError(t, (VersionFilter{PluginID: "mysql", Status: StatusVerified, Limit: 25}).Validate())
}

func TestAuditPayloadMatchesJSONBSemanticsWithoutLosingNumberPrecision(t *testing.T) {
	// Break caught: PostgreSQL JSONB reformatting must not make a durable Audit
	// payload conflict, while a changed actor or exact numeric value must.
	compact := []byte(`{"scope":{"tenant_id":"tenant-1"},"actor":"publisher","sequence":9007199254740993}`)
	jsonbStyle := []byte(`{ "sequence": 9007199254740993, "actor": "publisher", "scope": { "tenant_id": "tenant-1" } }`)
	require.True(t, AuditPayloadMatches(compact, jsonbStyle))
	require.False(t, AuditPayloadMatches(compact, []byte(`{"scope":{"tenant_id":"tenant-1"},"actor":"other","sequence":9007199254740993}`)))
	require.False(t, AuditPayloadMatches(compact, []byte(`{"scope":{"tenant_id":"tenant-1"},"actor":"publisher","sequence":9007199254740992}`)))
	require.False(t, AuditPayloadMatches(compact, []byte(`not-json`)))
}
