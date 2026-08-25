package telemetryv1_test

import (
	"os"
	"strings"
	"testing"
)

func TestTelemetryContractContainsRequiredOperations(t *testing.T) {
	body, err := os.ReadFile("telemetry.proto")
	if err != nil {
		t.Fatalf("read telemetry contract: %v", err)
	}

	for _, required := range []string{
		"rpc PushLogBatch", "rpc PushMetricBatch", "rpc ReportPolicyStatus",
		"batch_id", "agent_id", "source_id", "checksum", "retryable",
	} {
		if !strings.Contains(string(body), required) {
			t.Errorf("telemetry contract is missing %q", required)
		}
	}
}
