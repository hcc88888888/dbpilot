package agent

import (
	"context"
	"testing"
	"time"

	"dbpilot.local/platform/internal/database"
	"dbpilot.local/platform/internal/spool"
	"github.com/stretchr/testify/require"
)

func TestNewDependencyCollectorRejectsInvalidRuntimeBoundaries(t *testing.T) {
	valid := DependencyCollectorConfig{
		AgentID: "agent-a",
		Definitions: []database.ComponentDefinition{{
			ID: "hdfs-a", Kind: database.HDFSComponent,
			Endpoints: []database.Endpoint{{URL: "http://127.0.0.1:9870/jmx", Role: "namenode"}},
			SecretRef: "secret://test/reader",
		}},
		SecretResolver: database.StaticSecretResolver{"secret://test/reader": []byte("token")},
		Store:          discardDependencyStore{},
	}
	var typedNilStore *nilDependencyStore
	var typedNilResolver *nilDependencyResolver

	tests := map[string]func(*DependencyCollectorConfig){
		"missing secret resolver":  func(config *DependencyCollectorConfig) { config.SecretResolver = nil },
		"typed nil resolver":       func(config *DependencyCollectorConfig) { config.SecretResolver = typedNilResolver },
		"typed nil store":          func(config *DependencyCollectorConfig) { config.Store = typedNilStore },
		"negative interval":        func(config *DependencyCollectorConfig) { config.Interval = -time.Second },
		"negative timeout":         func(config *DependencyCollectorConfig) { config.RequestTimeout = -time.Second },
		"negative attempts":        func(config *DependencyCollectorConfig) { config.MaxAttempts = -1 },
		"negative initial backoff": func(config *DependencyCollectorConfig) { config.InitialBackoff = -time.Second },
		"negative maximum backoff": func(config *DependencyCollectorConfig) { config.MaxBackoff = -time.Second },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			collector, err := NewDependencyCollector(config)
			require.Error(t, err)
			require.Nil(t, collector)
		})
	}
}

type discardDependencyStore struct{}

func (discardDependencyStore) Append(context.Context, spool.DataClass, spool.Batch) error { return nil }

type nilDependencyStore struct{}

func (*nilDependencyStore) Append(context.Context, spool.DataClass, spool.Batch) error { return nil }

type nilDependencyResolver struct{}

func (*nilDependencyResolver) ResolveSecret(context.Context, string) ([]byte, error) { return nil, nil }
