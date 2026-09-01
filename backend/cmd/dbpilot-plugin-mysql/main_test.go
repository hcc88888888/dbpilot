package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArgumentsRequireSupervisorOwnedLaunchContract(t *testing.T) {
	values, ok := arguments([]string{"--runtime-dir", "/run/dbpilot/mysql", "--assignment-id", "assignment-a", "--plugin-id", "mysql", "--database-family", "mysql", "--version", "1.0.0", "--slot", "A", "--configuration-revision", "4", "--operation-revision", "9", "--instance-ids", `["mysql-a","mysql-b"]`, "--template-ids", `["custom-a"]`, "--launch-nonce-fd", "3"})
	require.True(t, ok)
	require.Equal(t, "/run/dbpilot/mysql", values["--runtime-dir"])
	_, ok = arguments([]string{"--runtime-dir", "/tmp"})
	require.False(t, ok)
	_, ok = arguments([]string{"--runtime-dir", "/tmp", "--runtime-dir", "/other"})
	require.False(t, ok)
	require.False(t, uniqueNonempty([]string{"mysql-a", "mysql-a"}))
	require.True(t, uniqueNonempty([]string{"mysql-a", "mysql-b"}))
}

func TestManifestTemplateMatchesRuntimeIdentityAndSignedCapabilityProjection(t *testing.T){body,err:=os.ReadFile("manifest.template.json");require.NoError(t,err);var manifest struct{PluginID string `json:"plugin_id"`;DatabaseFamily string `json:"database_family"`;Version string `json:"version"`;ProtocolVersion string `json:"protocol_version"`;SupportedVariants []string `json:"supported_variants"`;Capabilities []string `json:"capabilities"`;MetricTemplateSchemaVersion uint32 `json:"metric_template_schema_version"`};require.NoError(t,json.Unmarshal(body,&manifest));require.Equal(t,"mysql",manifest.PluginID);require.Equal(t,"mysql",manifest.DatabaseFamily);require.Equal(t,"1.0.0",manifest.Version);require.Equal(t,"v1",manifest.ProtocolVersion);require.Equal(t,[]string{"mysql"},manifest.SupportedVariants);require.Equal(t,[]string{"metrics.collect"},manifest.Capabilities);require.Equal(t,uint32(1),manifest.MetricTemplateSchemaVersion)}
