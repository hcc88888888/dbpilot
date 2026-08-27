package openapi

import (
	"strings"
	"testing"
)

func TestOperationPermissions(t *testing.T) {
	if got := OperationPermissions["getJob"]; got != "platform.jobs.read" {
		t.Fatalf("OperationPermissions[getJob] = %q, want %q", got, "platform.jobs.read")
	}

	document, err := GetSwagger()
	if err != nil {
		t.Fatalf("load bundled OpenAPI document: %v", err)
	}

	operationCount := 0
	for path, pathItem := range document.Paths.Map() {
		for method, operation := range pathItem.Operations() {
			operationCount++
			if operation.OperationID == "" {
				t.Errorf("%s %s has no operationId", method, path)
				continue
			}

			matchingPermissions := 0
			for operationID, permission := range OperationPermissions {
				if strings.EqualFold(operationID, operation.OperationID) {
					matchingPermissions++
					if permission == "" {
						t.Errorf("%s %s (%s) has an empty generated permission", method, path, operation.OperationID)
					}
				}
			}
			if matchingPermissions != 1 {
				t.Errorf("%s %s (%s) has %d generated permissions, want exactly 1", method, path, operation.OperationID, matchingPermissions)
			}
		}
	}

	if got := len(OperationPermissions); got != operationCount {
		t.Errorf("generated permission count = %d, bundled operation count = %d", got, operationCount)
	}
}
