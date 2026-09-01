package controlplanemigrations

import (
	"context"
	"errors"
	"testing"
	"time"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/inspection"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestRunMigrationStepsPreservesProductionOrderAndOptions(t *testing.T) {
	var order []string
	step := func(name string) func(context.Context) error {
		return func(context.Context) error {
			order = append(order, name)
			return nil
		}
	}
	steps := migrationSteps{
		alert:            step("alert"),
		job:              step("job"),
		platform:         step("platform"),
		host:             step("host"),
		discovery:        step("discovery"),
		databaseInstance: step("database-instance"),
		enrollment:       step("enrollment"),
		pluginCatalog:    step("plugin-catalog"),
		pluginAssignment: step("plugin-assignment"),
		credentialLease:  step("credential-lease"),
		inspection:       step("inspection"),
	}

	require.NoError(t, runMigrationSteps(context.Background(), Options{}, steps))
	require.Equal(t, []string{"alert", "job", "platform", "host", "discovery", "database-instance", "enrollment", "inspection"}, order)

	order = nil
	require.NoError(t, runMigrationSteps(context.Background(), Options{PluginCatalogEnabled: true, CredentialLeasesEnabled: true}, steps))
	require.Equal(t, []string{"alert", "job", "platform", "host", "discovery", "database-instance", "enrollment", "plugin-catalog", "plugin-assignment", "credential-lease", "inspection"}, order)
}

func TestRunMigrationStepsStopsAtFirstFailure(t *testing.T) {
	want := errors.New("database instance migration failed")
	var order []string
	step := func(name string, err error) func(context.Context) error {
		return func(context.Context) error {
			order = append(order, name)
			return err
		}
	}

	err := runMigrationSteps(context.Background(), Options{PluginCatalogEnabled: true, CredentialLeasesEnabled: true}, migrationSteps{
		alert:            step("alert", nil),
		job:              step("job", nil),
		platform:         step("platform", nil),
		host:             step("host", nil),
		discovery:        step("discovery", nil),
		databaseInstance: step("database-instance", want),
		enrollment:       step("enrollment", nil),
		pluginCatalog:    step("plugin-catalog", nil),
		pluginAssignment: step("plugin-assignment", nil),
		credentialLease:  step("credential-lease", nil),
		inspection:       step("inspection", nil),
	})

	require.ErrorIs(t, err, want)
	require.Equal(t, []string{"alert", "job", "platform", "host", "discovery", "database-instance"}, order)
}

func TestRunMigrationStepsFailsClosedWhenEnabledStepIsUnavailable(t *testing.T) {
	noop := func(context.Context) error { return nil }
	steps := migrationSteps{
		alert:            noop,
		job:              noop,
		platform:         noop,
		host:             noop,
		discovery:        noop,
		databaseInstance: noop,
		enrollment:       noop,
		pluginCatalog:    noop,
		pluginAssignment: noop,
		credentialLease:  noop,
		inspection:       noop,
	}

	steps.pluginAssignment = nil
	require.EqualError(t, runMigrationSteps(context.Background(), Options{PluginCatalogEnabled: true}, steps), "migration step is unavailable")

	steps.pluginAssignment = noop
	steps.credentialLease = nil
	require.EqualError(t, runMigrationSteps(context.Background(), Options{CredentialLeasesEnabled: true}, steps), "migration step is unavailable")

	steps.credentialLease = noop
	steps.inspection = nil
	require.EqualError(t, runMigrationSteps(context.Background(), Options{}, steps), "migration step is unavailable")
}

func TestSeedInspectionCatalogIsScopedAndIdempotent(t *testing.T) {
	store := &memoryInspectionCatalog{items: map[string]inspection.Item{}}
	now := time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)
	scopes := []alert.Scope{{TenantID: "tenant-a", ProjectID: "project-a"}, {TenantID: "tenant-b", ProjectID: "project-b"}}
	require.NoError(t, seedInspectionCatalog(context.Background(), store, scopes, now))
	require.Len(t, store.items, len(inspection.BuiltinHostItems())*2)
	for _, item := range store.items {
		require.NotEmpty(t, item.Scope.TenantID)
		require.True(t, item.Enabled)
		require.Equal(t, now, item.CreatedAt)
		require.Equal(t, now, item.UpdatedAt)
	}
	created := store.creates
	require.NoError(t, seedInspectionCatalog(context.Background(), store, scopes, now.Add(time.Hour)))
	require.Equal(t, created, store.creates, "restart must not create a second catalog version")
}

type memoryInspectionCatalog struct {
	items   map[string]inspection.Item
	creates int
}

func (store *memoryInspectionCatalog) CreateItem(_ context.Context, value inspection.Item) error {
	store.creates++
	store.items[value.Scope.Key()+"\x00"+value.ID] = value
	return nil
}

func (store *memoryInspectionCatalog) ListItems(_ context.Context, scope platformscope.Scope, filter inspection.ItemFilter) (inspection.ItemPage, error) {
	result := inspection.ItemPage{}
	for _, requested := range filter.Versions {
		if value, ok := store.items[scope.Key()+"\x00"+requested.ItemID]; ok && value.Version == requested.Version {
			result.Items = append(result.Items, value)
		}
	}
	return result, nil
}
