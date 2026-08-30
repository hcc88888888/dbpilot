package controlplane

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var task1UnimplementedOperationNames = []string{
	"AcceptDiscoveryCandidate",
	"ApproveMetricTemplateRevision",
	"ApprovePluginVersion",
	"CreateMetricTemplate",
	"CreateMetricTemplateRevision",
	"DecommissionHost",
	"GetDatabaseInstance",
	"GetDiscoveryCandidate",
	"GetHost",
	"GetPluginAssignment",
	"IgnoreDiscoveryCandidate",
	"ListDatabaseInstances",
	"ListDiscoveryCandidates",
	"ListHosts",
	"ListMetricTemplateRevisions",
	"ListMetricTemplates",
	"ListPluginAssignments",
	"ListPluginDefinitions",
	"ListPluginVersions",
	"PublishMetricTemplateRevision",
	"PublishPluginVersion",
	"ReconcilePluginAssignment",
	"RediscoverHost",
	"RetireDatabaseInstance",
	"RevokePluginVersion",
	"TestDatabaseInstanceConnection",
	"TrialMetricTemplateRevision",
	"UpdateDatabaseInstance",
	"UpdatePluginAssignment",
	"UploadPluginVersionPackage",
	"ValidateMetricTemplateRevision",
}

func TestTask1UnimplementedPlatformAPIInventory(t *testing.T) {
	adapter := unimplementedPlatformAPI{}
	adapterType := reflect.TypeOf(adapter)
	got := make([]string, 0, adapterType.NumMethod())
	for index := 0; index < adapterType.NumMethod(); index++ {
		method := adapterType.Method(index)
		got = append(got, method.Name)

		results := method.Func.Call([]reflect.Value{
			reflect.ValueOf(adapter),
			reflect.ValueOf(context.Background()),
			reflect.Zero(method.Type.In(2)),
		})
		require.Len(t, results, 2, method.Name)
		require.True(t, results[0].IsNil(), method.Name)
		err, ok := results[1].Interface().(error)
		require.True(t, ok, method.Name)
		require.ErrorIs(t, err, ErrServiceUnavailable, method.Name)
	}

	expected := append([]string(nil), task1UnimplementedOperationNames...)
	sort.Strings(expected)
	sort.Strings(got)
	require.Equal(t, expected, got)

	explicitPlatformMethods := explicitReceiverMethods(t, "platformAPI")
	for _, operation := range expected {
		require.NotContains(t, explicitPlatformMethods, operation, "%s must have exactly one implementation owner", operation)
	}
}

func explicitReceiverMethods(t *testing.T, receiverName string) map[string]struct{} {
	t.Helper()
	packages, err := parser.ParseDir(token.NewFileSet(), ".", func(info os.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	require.NoError(t, err)
	pkg := packages["controlplane"]
	require.NotNil(t, pkg)

	methods := make(map[string]struct{})
	for _, file := range pkg.Files {
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv == nil || len(function.Recv.List) != 1 {
				continue
			}
			if receiverTypeName(function.Recv.List[0].Type) == receiverName {
				methods[function.Name.Name] = struct{}{}
			}
		}
	}
	return methods
}

func receiverTypeName(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.StarExpr:
		return receiverTypeName(value.X)
	default:
		return ""
	}
}
