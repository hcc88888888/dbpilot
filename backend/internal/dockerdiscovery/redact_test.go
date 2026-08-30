package dockerdiscovery

import (
	"testing"
	"unicode/utf8"

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

func TestDockerRedactionCoversShortFlagsDSNHeadersAndEmbeddedURIs(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		forbidden []string
	}{
		{name: "short separate", arguments: []string{"mysql", "-p", "short-secret"}, forbidden: []string{"short-secret"}},
		{name: "long separate", arguments: []string{"mysql", "--password", "long-secret"}, forbidden: []string{"long-secret"}},
		{name: "dsn equal", arguments: []string{"app", "--dsn=alice:dsn-secret@tcp(db:3306)/app"}, forbidden: []string{"alice", "dsn-secret"}},
		{name: "database url next", arguments: []string{"app", "--database-url", "mysql://alice:url-secret@db/app?token=query-secret"}, forbidden: []string{"alice", "url-secret", "query-secret"}},
		{name: "embedded uri", arguments: []string{"app", "--endpoint=mysql://alice:embedded-secret@db/app?password=query-secret&tls=true"}, forbidden: []string{"alice", "embedded-secret", "query-secret"}},
		{name: "authorization", arguments: []string{"app", "--authorization", "Bearer header-secret"}, forbidden: []string{"header-secret"}},
		{name: "header", arguments: []string{"app", "-H", "Authorization: header-secret"}, forbidden: []string{"header-secret"}},
		{name: "attached header", arguments: []string{"app", "-HAuthorization:attached-secret"}, forbidden: []string{"attached-secret"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			summary := RedactCommand(test.arguments)
			for _, value := range test.forbidden {
				require.NotContains(t, summary, value)
			}
			require.Contains(t, summary, "[REDACTED]")
		})
	}
}

func TestDockerRedactionReturnsValidUTF8AtBoundaries(t *testing.T) {
	summary := RedactCommand([]string{string([]byte{'x', 0xff, 'y'}), "--endpoint=" + "界" + string(make([]byte, maximumCommandSummaryBytes))})
	require.True(t, utf8.ValidString(summary))
	require.LessOrEqual(t, len(summary), maximumCommandSummaryBytes)
}

func TestDockerLabelValuesScrubEmbeddedURIAndSensitiveQuery(t *testing.T) {
	labels := FilterLabels(map[string]string{"dbpilot.connection.hint": "mysql://alice:label-secret@db/app?token=query-secret&tls=true"}, []string{"dbpilot.connection.hint"})
	value := labels["dbpilot.connection.hint"]
	require.NotContains(t, value, "alice")
	require.NotContains(t, value, "label-secret")
	require.NotContains(t, value, "query-secret")
	require.Contains(t, value, "[REDACTED]")
}

func TestDockerRedactionCoversBareAndEmbeddedDSNGrammars(t *testing.T) {
	tests := []struct {
		name, value string
		forbidden   []string
	}{
		{name: "go mysql positional", value: "alice:mysql-secret@tcp(db:3306)/app", forbidden: []string{"alice", "mysql-secret"}},
		{name: "go mysql arbitrary option", value: "--target=alice:mysql-secret@tcp(db:3306)/app?tls=true", forbidden: []string{"alice", "mysql-secret"}},
		{name: "go mysql escaped", value: "alice%40corp:secret%3Avalue@tcp(db:3306)/app", forbidden: []string{"alice%40corp", "secret%3Avalue"}},
		{name: "oracle easy connect", value: "scott/oracle-secret@db:1521/service", forbidden: []string{"scott", "oracle-secret"}},
		{name: "postgres keyword", value: "user=alice password=pg-secret host=db dbname=app", forbidden: []string{"alice", "pg-secret"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			summary := RedactCommand([]string{"app", test.value})
			for _, forbidden := range test.forbidden {
				require.NotContains(t, summary, forbidden)
			}
			require.Contains(t, summary, "[REDACTED]")
			labels := FilterLabels(map[string]string{"dbpilot.hint": test.value}, []string{"dbpilot.hint"})
			for _, forbidden := range test.forbidden {
				require.NotContains(t, labels["dbpilot.hint"], forbidden)
			}
		})
	}
}

func TestDockerDSNRedactionAvoidsOrdinaryTextFalsePositives(t *testing.T) {
	for _, value := range []string{"meeting:owner@example.com", "artifact@tcp.example.com/path", "host=db dbname=app", "12:30 schedule"} {
		require.Contains(t, RedactCommand([]string{"app", value}), value)
	}
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
