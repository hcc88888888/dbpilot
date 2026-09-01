// Package controlplanemigrations owns the production control-plane migration
// composition so startup and integration tests execute the same pipeline.
package controlplanemigrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/credentiallease"
	"dbpilot.local/platform/internal/databaseinstance"
	"dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/enrollment"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/inspection"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/metrictemplate"
	"dbpilot.local/platform/internal/platformdb"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/pluginassignment"
	"dbpilot.local/platform/internal/plugincatalog"
)

type Options struct {
	PluginCatalogEnabled    bool
	CredentialLeasesEnabled bool
	InspectionScopes        []alert.Scope
	Now                     func() time.Time
}

type migrationSteps struct {
	alert            func(context.Context) error
	job              func(context.Context) error
	platform         func(context.Context) error
	host             func(context.Context) error
	discovery        func(context.Context) error
	databaseInstance func(context.Context) error
	enrollment       func(context.Context) error
	pluginCatalog    func(context.Context) error
	pluginAssignment func(context.Context) error
	metricTemplate   func(context.Context) error
	credentialLease  func(context.Context) error
	inspection       func(context.Context) error
}

func Run(ctx context.Context, database *sql.DB, options Options) error {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	steps := migrationSteps{
		alert:            func(ctx context.Context) error { return alert.RunMigrations(ctx, database) },
		job:              func(ctx context.Context) error { return job.RunMigrations(ctx, database) },
		platform:         func(ctx context.Context) error { return platformdb.RunMigrations(ctx, database) },
		host:             func(ctx context.Context) error { return hostinventory.RunMigrations(ctx, database) },
		discovery:        func(ctx context.Context) error { return discovery.RunMigrations(ctx, database) },
		databaseInstance: func(ctx context.Context) error { return databaseinstance.RunMigrations(ctx, database) },
		enrollment:       func(ctx context.Context) error { return enrollment.RunMigrations(ctx, database) },
		pluginCatalog:    func(ctx context.Context) error { return plugincatalog.RunMigrations(ctx, database) },
		pluginAssignment: func(ctx context.Context) error { return pluginassignment.RunMigrations(ctx, database) },
		metricTemplate:   func(ctx context.Context) error { return metrictemplate.RunMigrations(ctx, database) },
		credentialLease:  func(ctx context.Context) error { return credentiallease.RunMigrations(ctx, database) },
		inspection: func(ctx context.Context) error {
			if err := inspection.RunMigrations(ctx, database); err != nil {
				return err
			}
			return seedInspectionCatalog(ctx, inspection.NewPostgresRepository(database, nil), options.InspectionScopes, now().UTC())
		},
	}
	return runMigrationSteps(ctx, options, steps)
}

func runMigrationSteps(ctx context.Context, options Options, steps migrationSteps) error {
	pipeline := []func(context.Context) error{steps.alert, steps.job, steps.platform, steps.host, steps.discovery, steps.databaseInstance, steps.enrollment}
	if options.PluginCatalogEnabled {
		pipeline = append(pipeline, steps.pluginCatalog, steps.pluginAssignment, steps.metricTemplate)
	}
	if options.CredentialLeasesEnabled {
		pipeline = append(pipeline, steps.credentialLease)
	}
	pipeline = append(pipeline, steps.inspection)
	for _, step := range pipeline {
		if step == nil {
			return errors.New("migration step is unavailable")
		}
		if err := step(ctx); err != nil {
			return err
		}
	}
	return nil
}

type inspectionCatalogStore interface {
	CreateItem(context.Context, inspection.Item) error
	ListItems(context.Context, platformscope.Scope, inspection.ItemFilter) (inspection.ItemPage, error)
}

func seedInspectionCatalog(ctx context.Context, store inspectionCatalogStore, scopes []alert.Scope, now time.Time) error {
	if ctx == nil || store == nil || now.IsZero() || now.Location() != time.UTC {
		return errors.New("inspection catalog seed input is invalid")
	}
	for _, configured := range scopes {
		scope := platformscope.Scope{TenantID: configured.TenantID, ProjectID: configured.ProjectID}
		if scope.Validate() != nil {
			return errors.New("inspection catalog scope is invalid")
		}
		for _, item := range inspection.BuiltinHostItems() {
			filter := inspection.ItemFilter{CursorFilter: inspection.CursorFilter{Limit: 2}, Versions: []inspection.PolicyItem{{ItemID: item.ID, Version: item.Version}}}
			page, err := store.ListItems(ctx, scope, filter)
			if err != nil {
				return fmt.Errorf("list inspection catalog item: %w", err)
			}
			if len(page.Items) == 1 && page.Items[0].ID == item.ID && page.Items[0].Version == item.Version && page.Items[0].Scope == scope {
				continue
			}
			if len(page.Items) != 0 {
				return errors.New("inspection catalog item is inconsistent")
			}
			item.Scope, item.Enabled, item.CreatedAt, item.UpdatedAt = scope, true, now, now
			if err := store.CreateItem(ctx, item); err != nil {
				page, readErr := store.ListItems(ctx, scope, filter)
				if readErr != nil || len(page.Items) != 1 || page.Items[0].ID != item.ID || page.Items[0].Version != item.Version || page.Items[0].Scope != scope {
					return fmt.Errorf("create inspection catalog item: %w", err)
				}
			}
		}
	}
	return nil
}
