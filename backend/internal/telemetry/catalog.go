// Package telemetry compiles validated DBPilot policies into a closed set of
// embedded OpenTelemetry Collector component configurations.
package telemetry

import (
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/storage/filestorage"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/filterprocessor"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/filelogreceiver"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/hostmetricsreceiver"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/journaldreceiver"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/batchprocessor"
	"go.opentelemetry.io/collector/processor/memorylimiterprocessor"
	"go.opentelemetry.io/collector/receiver"
)

// Catalog is the deliberately closed component allow-list used by Compile.
// It does not accept arbitrary factories or component type names.
type Catalog interface {
	ReceiverFactory(name string) (receiver.Factory, bool)
	ProcessorFactory(name string) (processor.Factory, bool)
}

type catalog struct {
	receivers   map[string]receiver.Factory
	processors  map[string]processor.Factory
	fileStorage extension.Factory
}

// NewCatalog returns factories for exactly the components DBPilot embeds.
func NewCatalog() Catalog {
	return &catalog{
		receivers: map[string]receiver.Factory{
			"file_log":     filelogreceiver.NewFactory(),
			"journald":     journaldreceiver.NewFactory(),
			"host_metrics": hostmetricsreceiver.NewFactory(),
			"prometheus":   prometheusreceiver.NewFactory(),
		},
		processors: map[string]processor.Factory{
			"memory_limiter": memorylimiterprocessor.NewFactory(),
			"batch":          batchprocessor.NewFactory(),
			"filter":         filterprocessor.NewFactory(),
			"transform":      transformprocessor.NewFactory(),
		},
		fileStorage: filestorage.NewFactory(),
	}
}

func (c *catalog) ReceiverFactory(name string) (receiver.Factory, bool) {
	factory, ok := c.receivers[name]
	return factory, ok
}

func (c *catalog) ProcessorFactory(name string) (processor.Factory, bool) {
	factory, ok := c.processors[name]
	return factory, ok
}

func (c *catalog) fileStorageFactory() extension.Factory {
	return c.fileStorage
}
