package dockerdiscovery

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDockerCommandSummaryRedactsCredentialFormsBeforeDTO(t *testing.T) {
	arguments := []string{"mysqld", "--password=top-secret", "--user", "monitor", "--token", "bearer-value", "mysql://alice:hunter2@db:3306/app", "MYSQL_PWD=value", "-pshort"}
	summary := RedactCommand(arguments)
	require.NotContains(t, summary, "top-secret")
	require.NotContains(t, summary, "bearer-value")
	require.NotContains(t, summary, "hunter2")
	require.NotContains(t, summary, "MYSQL_PWD=value")
	require.NotContains(t, summary, "-pshort")
	require.Contains(t, summary, "[REDACTED]")
	require.LessOrEqual(t, len(summary), maximumCommandSummaryBytes)
}

func TestDockerLabelsAreStrictlyAllowlistedAndCredentialValuesStillRedacted(t *testing.T) {
	labels := FilterLabels(map[string]string{
		"dbpilot.discovery.family": "mysql",
		"dbpilot.run":              "run-01",
		"password":                 "hidden",
		"unapproved":               "also-hidden",
	}, []string{"dbpilot.discovery.family", "dbpilot.run", "password"})
	require.Equal(t, map[string]string{"dbpilot.discovery.family": "mysql", "dbpilot.run": "run-01", "password": "[REDACTED]"}, labels)
}
