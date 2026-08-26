package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"dbpilot.local/platform/internal/agent"
	"dbpilot.local/platform/internal/policy"
	"dbpilot.local/platform/internal/spool"
	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("hbase-agent-fixture", flag.ContinueOnError)
	mode := flags.String("mode", "", "prepare or inspect")
	directory := flags.String("dir", "", "fixture directory")
	hbase := flags.String("hbase", "", "healthy HBase JMX URL")
	hbaseFailing := flags.String("hbase-failing", "", "failing HBase JMX URL")
	hdfs := flags.String("hdfs", "", "HDFS JMX URL")
	zookeeper := flags.String("zookeeper", "", "ZooKeeper JMX URL")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !filepath.IsAbs(*directory) {
		return errors.New("--dir must be absolute")
	}
	switch *mode {
	case "prepare":
		return prepare(*directory, *hbase, *hbaseFailing, *hdfs, *zookeeper)
	case "inspect":
		return inspect(*directory)
	default:
		return errors.New("--mode must be prepare or inspect")
	}
}

func prepare(directory, hbase, hbaseFailing, hdfs, zookeeper string) error {
	for _, endpoint := range []string{hbase, hbaseFailing, hdfs, zookeeper} {
		if endpoint == "" {
			return errors.New("all fixture endpoints are required")
		}
	}
	if err := os.MkdirAll(filepath.Join(directory, "spool"), 0o700); err != nil {
		return err
	}
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "DBPilot Fixture CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	identity, _ := url.Parse("spiffe://dbpilot/agent/agent-kylin")
	clientTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "agent-kylin"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), URIs: []*url.URL{identity}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, ca, clientPublic, caPrivate)
	if err != nil {
		return err
	}
	clientKey, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		return err
	}
	policyPublic, policyPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	policyKey, err := x509.MarshalPKIXPublicKey(policyPublic)
	if err != nil {
		return err
	}
	envelope, err := policy.Sign(policyPrivate, policy.Policy{AgentID: "agent-kylin", Version: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Sources: []policy.Source{{ID: "host", Kind: policy.SourceHostMetrics, Interval: time.Hour}}, Limits: policy.Limits{MaxSpoolBytes: 1 << 20, MaxBatchBytes: 1 << 16, MaxEventsPerSec: 100}})
	if err != nil {
		return err
	}
	policyJSON, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"ca.pem":            pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		"agent.pem":         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}),
		"agent-key.pem":     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKey}),
		"policy-public.pem": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: policyKey}),
		"policy.json":       policyJSON,
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(directory, name), contents, 0o600); err != nil {
			return err
		}
	}
	config := map[string]any{
		"agent_id": "agent-kylin", "server_address": "127.0.0.1:1", "ca_file": filepath.Join(directory, "ca.pem"), "cert_file": filepath.Join(directory, "agent.pem"), "key_file": filepath.Join(directory, "agent-key.pem"),
		"policy_public_key_file": filepath.Join(directory, "policy-public.pem"), "policy_file": filepath.Join(directory, "policy.json"), "data_directory": filepath.Join(directory, "spool"), "file_collection_enabled": false,
		"component_secrets": map[string]any{"provider": "environment"}, "component_collection": map[string]any{"interval_seconds": 3600, "request_timeout_seconds": 2, "max_attempts": 2, "initial_backoff_milliseconds": 10, "max_backoff_milliseconds": 20},
		"components": []any{
			map[string]any{"id": "hdfs-prod", "kind": "hdfs", "endpoints": []any{map[string]any{"url": hdfs, "role": "datanode"}}, "secret_ref": "secret://fixture/reader"},
			map[string]any{"id": "zk-prod", "kind": "zookeeper", "endpoints": []any{map[string]any{"url": zookeeper, "role": "leader"}}, "secret_ref": "secret://fixture/reader"},
			map[string]any{"id": "hbase-prod", "kind": "hbase", "endpoints": []any{map[string]any{"url": hbase, "role": "regionserver"}, map[string]any{"url": hbaseFailing, "role": "regionserver"}}, "secret_ref": "secret://fixture/reader", "dependencies": map[string]any{"hdfs_cluster_id": "hdfs-prod", "zookeeper_cluster_id": "zk-prod"}},
		},
	}
	body, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, "agent.yaml"), body, 0o600)
}

func inspect(directory string) error {
	store, err := spool.Open(filepath.Join(directory, "spool"), spool.Limits{MaxBytes: 1 << 30, SegmentBytes: 16 << 20})
	if err != nil {
		return err
	}
	defer store.Close()
	batches, err := store.Pending(context.Background(), spool.Metric, 100)
	if err != nil {
		return err
	}
	for _, batch := range batches {
		if batch.SourceID != "hbase-dependencies" {
			continue
		}
		var envelope agent.DependencyTelemetryEnvelope
		if err := json.Unmarshal(batch.Payload, &envelope); err != nil {
			return err
		}
		if len(envelope.Samples) == 0 || len(envelope.Evidence) == 0 {
			return errors.New("dependency envelope lacks samples or evidence")
		}
		for _, status := range envelope.Statuses {
			if status.Cluster == "hbase-prod" && status.State == "partial" && status.Attempts == 2 {
				fmt.Printf("verified dependency batch %s sequence=%d samples=%d evidence=%d\n", batch.ID, envelope.Sequence, len(envelope.Samples), len(envelope.Evidence))
				return nil
			}
		}
		return errors.New("dependency envelope lacks retried partial HBase status")
	}
	return errors.New("dependency metric batch was not delivered to the spool")
}
