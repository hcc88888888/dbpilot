package database

const postgresDriverName = "postgres"

// NewPostgresFactory creates adapters for explicitly selected PostgreSQL-
// protocol families, including openGauss. The fixed driver name is selected by
// this factory, never by instance configuration.
func NewPostgresFactory(opener SQLOpener, catalog TemplateCatalog) Factory {
	return &sqlProtocolFactory{
		protocol: postgresDriverName,
		opener:   opener,
		catalog:  catalog,
		capabilities: CapabilityMatrix{
			ReadOnlySQL:  true,
			Metrics:      true,
			Transactions: true,
		},
	}
}
