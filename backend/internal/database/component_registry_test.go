package database

import (
	"context"
	"testing"
)

func TestComponentRegistryRejectsInvalidKind(t *testing.T) {
	r := NewComponentRegistry()
	definition := validComponentDefinition()
	definition.Kind = ComponentKind("redis")
	if err := r.Register(definition, &fakeComponentAdapter{}); err == nil {
		t.Fatal("Register() error = nil, want invalid component kind rejection")
	}
}

func TestComponentRegistryRejectsNonCanonicalSecretReferences(t *testing.T) {
	for _, ref := range []string{"password", "secret://runtime", "secret://runtime/a/b", "secret://runtime/a?version=1"} {
		t.Run(ref, func(t *testing.T) {
			r := NewComponentRegistry()
			definition := validComponentDefinition()
			definition.SecretRef = ref
			if err := r.Register(definition, &fakeComponentAdapter{}); err == nil {
				t.Fatal("Register() error = nil, want malformed secret reference rejection")
			}
		})
	}
}

func TestComponentRegistryAuthorizesDependencies(t *testing.T) {
	r := NewComponentRegistry()
	for _, definition := range []ComponentDefinition{
		{ID: "hdfs-prod", Kind: HDFSComponent, SecretRef: "secret://runtime/hdfs", Endpoints: []Endpoint{{URL: "http://hdfs.example.test:9870/jmx"}}},
		{ID: "zk-prod", Kind: ZooKeeperComponent, SecretRef: "secret://runtime/zk", Endpoints: []Endpoint{{URL: "http://zk.example.test:8080/jmx"}}},
	} {
		if err := r.Register(definition, &fakeComponentAdapter{}); err != nil {
			t.Fatalf("Register(%q) error = %v", definition.ID, err)
		}
	}
	hbase := validComponentDefinition()
	hbase.Dependencies = DependencyRef{HDFSClusterID: "hdfs-prod", ZooKeeperClusterID: "zk-prod"}
	if err := r.Register(hbase, &fakeComponentAdapter{}); err != nil {
		t.Fatalf("Register(HBase) error = %v", err)
	}
	missing := hbase
	missing.ID = "hbase-missing"
	missing.Dependencies.HDFSClusterID = "unknown"
	if err := r.Register(missing, &fakeComponentAdapter{}); err == nil {
		t.Fatal("Register() error = nil, want unauthorized dependency rejection")
	}
}

func TestComponentRegistryRejectsTypedNilAdapter(t *testing.T) {
	r := NewComponentRegistry()
	var adapter *fakeComponentAdapter
	if err := r.Register(validComponentDefinition(), adapter); err == nil {
		t.Fatal("Register() error = nil, want typed-nil adapter rejection")
	}
}

func validComponentDefinition() ComponentDefinition {
	return ComponentDefinition{ID: "hbase-prod", Kind: HBaseComponent, SecretRef: "secret://runtime/hbase", Endpoints: []Endpoint{{URL: "http://hbase.example.test:16010/jmx"}}}
}

type fakeComponentAdapter struct{}
func (*fakeComponentAdapter) Component() ComponentKind { return HBaseComponent }
func (*fakeComponentAdapter) Capabilities() CapabilityMatrix { return CapabilityMatrix{} }
func (*fakeComponentAdapter) Ping(context.Context) error { return nil }
func (*fakeComponentAdapter) Collect(context.Context, MetricRequest) ([]MetricSample, error) { return nil, nil }
func (*fakeComponentAdapter) Close() error { return nil }
