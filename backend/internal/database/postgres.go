package database

const postgresDriverName = "postgres"

// NewPostgresFactory creates adapters for explicitly selected PostgreSQL-
// protocol families, including openGauss. The fixed driver name is selected by
// this factory, never by instance configuration.
func NewPostgresFactory(opener SQLOpener, catalog TemplateCatalog) Factory {
	return NewPostgresFactoryWithRuntime(opener, catalog, nil)
}

// NewPostgresFactoryWithRuntime creates a PostgreSQL-protocol factory with a
// runtime-only resolver for credential and TLS material.
func NewPostgresFactoryWithRuntime(opener SQLOpener, catalog TemplateCatalog, resolver SecretResolver) Factory {
	return &sqlProtocolFactory{
		protocol: postgresDriverName,
		opener:   opener,
		catalog:  catalog,
		resolver: resolver,
		capabilities: CapabilityMatrix{
			ReadOnlySQL:  true,
			Metrics:      true,
			Transactions: true,
		},
	}
}
