import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const redoclyCli = join(repoRoot, 'node_modules', '@redocly', 'cli', 'bin', 'cli.js');

async function bundleContract() {
  const directory = await mkdtemp(join(tmpdir(), 'dbpilot-host-plugin-openapi-'));
  const output = join(directory, 'dbpilot-api.json');
  try {
    const result = spawnSync(process.execPath, [
      redoclyCli, 'bundle', 'contracts/openapi/dbpilot-api.yaml', '--ext', 'json', '--output', output,
    ], { cwd: repoRoot, encoding: 'utf8' });
    if (result.error) throw result.error;
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(await readFile(output, 'utf8'));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function operations(document) {
  return new Map(Object.values(document.paths).flatMap((pathItem) =>
    Object.entries(pathItem)
      .filter(([method]) => ['get', 'post', 'patch'].includes(method))
      .map(([, operation]) => [operation.operationId, operation]),
  ));
}

function operationInventory(document) {
  return Object.entries(document.paths).flatMap(([path, pathItem]) =>
    Object.entries(pathItem)
      .filter(([method]) => ['get', 'post', 'patch'].includes(method))
      .map(([method, operation]) => ({ path, method, operation })),
  );
}

function requiredHeader(operation, name) {
  const header = operation.parameters?.find((parameter) => parameter.in === 'header' && parameter.name === name);
  assert.ok(header, `${operation.operationId} declares ${name}`);
  assert.equal(header.required, true, `${operation.operationId} requires ${name}`);
}

function resolvedSchema(document, schema) {
  if (!schema?.$ref) return schema;
  return document.components.schemas[schema.$ref.replace('#/components/schemas/', '')];
}

function visitResolvedSchema(document, schema, path, visitor, seen = new Set()) {
  if (!schema) return;
  if (schema.$ref) {
    if (seen.has(schema.$ref)) return;
    const nextSeen = new Set(seen).add(schema.$ref);
    visitResolvedSchema(document, resolvedSchema(document, schema), path, visitor, nextSeen);
    return;
  }
  visitor(schema, path);
  for (const [name, property] of Object.entries(schema.properties ?? {})) {
    visitResolvedSchema(document, property, `${path}.${name}`, visitor, new Set(seen));
  }
  if (schema.items) visitResolvedSchema(document, schema.items, `${path}[]`, visitor, new Set(seen));
  if (typeof schema.additionalProperties === 'object') {
    visitResolvedSchema(document, schema.additionalProperties, `${path}{}`, visitor, new Set(seen));
  }
  for (const [index, alternative] of (schema.oneOf ?? []).entries()) {
    visitResolvedSchema(document, alternative, `${path}.oneOf[${index}]`, visitor, new Set(seen));
  }
}

test('host plugin platform exposes the complete exact operation inventory', async () => {
  const document = await bundleContract();
  const prefixes = ['hosts:', 'discovery:', 'database-instances:', 'plugins:', 'metric-templates:'];
  const actual = operationInventory(document)
    .filter(({ operation }) => prefixes.some((prefix) => operation['x-dbpilot-permission']?.startsWith(prefix)))
    .map(({ path, method, operation }) => [path, method, operation.operationId, operation['x-dbpilot-permission']])
    .sort((left, right) => left[2].localeCompare(right[2]));
  const expected = [
    ['/host-enrollments', 'post', 'createHostEnrollment', 'hosts:manage'],
    ['/host-enrollments/{host_id}/actions/replace', 'post', 'replaceHostEnrollment', 'hosts:manage'],
    ['/discovery-candidates/{candidate_id}/actions/accept', 'post', 'acceptDiscoveryCandidate', 'discovery:manage'],
    ['/plugin-versions/{version_id}/actions/approve', 'post', 'approvePluginVersion', 'plugins:approve'],
    ['/metric-template-revisions/{revision_id}/actions/approve', 'post', 'approveMetricTemplateRevision', 'metric-templates:approve'],
    ['/metric-templates', 'post', 'createMetricTemplate', 'metric-templates:manage'],
    ['/metric-templates/{template_id}/revisions', 'post', 'createMetricTemplateRevision', 'metric-templates:manage'],
    ['/hosts/{host_id}/actions/decommission', 'post', 'decommissionHost', 'hosts:manage'],
    ['/discovery-candidates/{candidate_id}', 'get', 'getDiscoveryCandidate', 'discovery:view'],
    ['/database-instances/{instance_id}', 'get', 'getDatabaseInstance', 'database-instances:view'],
    ['/hosts/{host_id}', 'get', 'getHost', 'hosts:view'],
    ['/plugin-assignments/{assignment_id}', 'get', 'getPluginAssignment', 'plugins:view'],
    ['/discovery-candidates/{candidate_id}/actions/ignore', 'post', 'ignoreDiscoveryCandidate', 'discovery:manage'],
    ['/discovery-candidates', 'get', 'listDiscoveryCandidates', 'discovery:view'],
    ['/database-instances', 'get', 'listDatabaseInstances', 'database-instances:view'],
    ['/hosts', 'get', 'listHosts', 'hosts:view'],
    ['/metric-templates/{template_id}/revisions', 'get', 'listMetricTemplateRevisions', 'metric-templates:view'],
    ['/metric-templates', 'get', 'listMetricTemplates', 'metric-templates:view'],
    ['/plugin-assignments', 'get', 'listPluginAssignments', 'plugins:view'],
    ['/plugin-definitions', 'get', 'listPluginDefinitions', 'plugins:view'],
    ['/plugin-versions', 'get', 'listPluginVersions', 'plugins:view'],
    ['/plugin-versions/{version_id}/actions/publish', 'post', 'publishPluginVersion', 'plugins:publish'],
    ['/metric-template-revisions/{revision_id}/actions/publish', 'post', 'publishMetricTemplateRevision', 'metric-templates:approve'],
    ['/plugin-assignments/{assignment_id}/actions/reconcile', 'post', 'reconcilePluginAssignment', 'plugins:deploy'],
    ['/hosts/{host_id}/actions/rediscover', 'post', 'rediscoverHost', 'hosts:discover'],
    ['/database-instances/{instance_id}/actions/retire', 'post', 'retireDatabaseInstance', 'database-instances:manage'],
    ['/plugin-versions/{version_id}/actions/revoke', 'post', 'revokePluginVersion', 'plugins:publish'],
    ['/database-instances/{instance_id}/actions/test-connection', 'post', 'testDatabaseInstanceConnection', 'database-instances:test'],
    ['/metric-template-revisions/{revision_id}/actions/trial', 'post', 'trialMetricTemplateRevision', 'metric-templates:manage'],
    ['/database-instances/{instance_id}', 'patch', 'updateDatabaseInstance', 'database-instances:manage'],
    ['/plugin-assignments/{assignment_id}', 'patch', 'updatePluginAssignment', 'plugins:manage'],
    ['/plugin-versions', 'post', 'uploadPluginVersionPackage', 'plugins:publish'],
    ['/metric-template-revisions/{revision_id}/actions/validate', 'post', 'validateMetricTemplateRevision', 'metric-templates:manage'],
  ].sort((left, right) => left[2].localeCompare(right[2]));
  assert.deepEqual(actual, expected);

  const writes = actual.filter(([, method]) => method !== 'get').map(([, , operationId]) => operationId);
  const byId = operations(document);
  for (const operationId of writes) requiredHeader(byId.get(operationId), 'Idempotency-Key');
  for (const operationId of [
    'decommissionHost', 'updateDatabaseInstance', 'retireDatabaseInstance', 'approvePluginVersion',
    'publishPluginVersion', 'revokePluginVersion', 'updatePluginAssignment', 'validateMetricTemplateRevision',
    'approveMetricTemplateRevision', 'publishMetricTemplateRevision',
  ]) requiredHeader(byId.get(operationId), 'If-Match');
});

test('host enrollment admin contract returns one bounded one-time token', async () => {
  const document = await bundleContract();
  const create = operations(document).get('createHostEnrollment');
  assert.ok(create, 'createHostEnrollment is generated from the platform contract');
  assert.equal(create.requestBody.required, true);
  assert.equal(create.requestBody.content['application/json'].schema.$ref, '#/components/schemas/CreateHostEnrollmentRequest');
  assert.equal(create.responses['201'].content['application/json'].schema.$ref, '#/components/schemas/HostEnrollment');
  const request = document.components.schemas.CreateHostEnrollmentRequest;
  assert.equal(request.additionalProperties, false);
  assert.deepEqual(request.required, ['host_id', 'agent_id', 'display_name', 'expires_in_seconds']);
  assert.equal(request.properties.expires_in_seconds.minimum, 60);
  assert.equal(request.properties.expires_in_seconds.maximum, 3600);
  const response = document.components.schemas.HostEnrollment;
  assert.equal(response.additionalProperties, false);
  assert.deepEqual(response.required, ['host_id', 'agent_id', 'enrollment_token', 'expires_at', 'enrollment_revision', 'generation']);
  assert.equal(response.properties.enrollment_token.minLength, 43);
  assert.equal(response.properties.enrollment_token.maxLength, 43);
  assert.equal(response.properties.enrollment_token.pattern, '^[A-Za-z0-9_-]{43}$');
});

test('host enrollment replacement is explicit and generation fenced', async () => {
  const document = await bundleContract();
  const actual = operations(document);
  const create = actual.get('createHostEnrollment');
  assert.ok(create.responses['409'].headers.ETag);
  assert.notEqual(create.responses['409'].headers.ETag.required, true, 'generic idempotency conflicts have no current generation');
  const replace = actual.get('replaceHostEnrollment');
  assert.ok(replace);
  requiredHeader(replace, 'Idempotency-Key');
  requiredHeader(replace, 'If-Match');
  assert.equal(replace.requestBody.content['application/json'].schema.$ref, '#/components/schemas/ReplaceHostEnrollmentRequest');
  assert.equal(replace.responses['201'].content['application/json'].schema.$ref, '#/components/schemas/HostEnrollment');
  assert.ok(replace.responses['409'].headers.ETag);
  assert.notEqual(replace.responses['409'].headers.ETag.required, true, 'generic idempotency conflicts have no correlated generation');
  assert.ok(document.components.schemas.HostEnrollment.required.includes('generation'));
  assert.equal(document.components.schemas.HostEnrollment.properties.generation.minimum, 1);
});

test('plugin version upload is bounded streaming and lifecycle actions expose manifest-derived state', async () => {
  const document = await bundleContract();
  const actual = operations(document);
  const upload = actual.get('uploadPluginVersionPackage');
  const body = upload.requestBody.content['application/gzip'].schema;
  assert.equal(body.type, 'string');
  assert.equal(body.format, 'binary');
  assert.equal(body.maxLength, 268435456);
  const contentLength = upload.parameters.find((item) => item.in === 'header' && item.name === 'Content-Length');
  assert.equal(contentLength.required, true);
  assert.equal(contentLength.schema.maximum, 268435456);
  for (const operationId of ['approvePluginVersion', 'publishPluginVersion', 'revokePluginVersion']) {
    assert.equal(actual.get(operationId).responses['200'].content['application/json'].schema.$ref, '#/components/schemas/PluginVersion');
  }
  const version = document.components.schemas.PluginVersion;
  for (const field of ['supported_variants', 'database_version_range', 'capabilities', 'metric_template_schema_version']) {
    assert.ok(version.required.includes(field), `PluginVersion requires manifest-derived ${field}`);
  }
  assert.equal(version.properties.supported_variants.maxItems, 16);
  assert.equal(version.properties.capabilities.maxItems, 64);
});

test('database retirement and synchronous template validation expose exact CAS responses', async () => {
  const document = await bundleContract();
  const actual = operations(document);
  const retire = actual.get('retireDatabaseInstance');
  assert.equal(retire.responses['200'].content['application/json'].schema.$ref, '#/components/schemas/ManagedDatabaseInstance');
  assert.equal(retire.responses['200'].headers.ETag.required, true);
  const validate = actual.get('validateMetricTemplateRevision');
  assert.equal(validate.responses['200'].content['application/json'].schema.$ref, '#/components/schemas/MetricTemplateRevision');
  assert.equal(validate.responses['200'].headers.ETag.required, true);
  assert.equal(validate.responses['202'], undefined);
});

test('plugin reconciliation success identifies the persisted job version', async () => {
  const document = await bundleContract();
  const reconcile = operations(document).get('reconcilePluginAssignment');
  assert.equal(reconcile.responses['202'].content['application/json'].schema.$ref, '#/components/schemas/Job');
  assert.equal(reconcile.responses['202'].headers.Location.required, true);
  assert.equal(reconcile.responses['202'].headers.ETag.required, true);
  assert.equal(reconcile.responses['202'].headers.ETag.schema.minLength, 3);
  assert.equal(reconcile.responses['202'].headers.ETag.schema.maxLength, 128);
});

test('host database plugin and metric template DTOs are closed and bounded', async () => {
  const document = await bundleContract();
  const schemas = document.components.schemas;

  assert.deepEqual(schemas.HostStatus.enum, ['pending', 'enrolling', 'online', 'stale', 'offline', 'decommissioned']);
  assert.deepEqual(schemas.DiscoveryCandidateStatus.enum, [
    'discovered', 'awaiting_confirmation', 'accepted', 'provisioning', 'ignored', 'duplicate', 'disappeared',
  ]);
  assert.deepEqual(schemas.DatabaseManagementStatus.enum, [
    'accepted', 'provisioning', 'connection_testing', 'managed', 'monitoring', 'plugin_failed',
    'authentication_failed', 'tls_failed', 'unreachable', 'unsupported_version', 'degraded', 'offline', 'retired',
  ]);
  assert.deepEqual(schemas.PluginVersionStatus.enum, [
    'uploaded', 'verified', 'approved', 'available', 'deprecated', 'revoked', 'rejected',
  ]);
  assert.deepEqual(schemas.PluginDesiredState.enum, ['absent', 'installed', 'running', 'stopped']);
  assert.deepEqual(schemas.MetricTemplateRevisionStatus.enum, [
    'draft', 'validating', 'validated', 'trial_running', 'trial_passed', 'approval_pending',
    'approved', 'published', 'superseded', 'validation_failed', 'trial_failed', 'rejected',
  ]);

  for (const name of [
    'ManagedHost', 'DiscoveryCandidate', 'ManagedDatabaseInstance', 'PluginDefinition',
    'PluginVersion', 'PluginAssignment', 'PluginObservedState', 'MetricTemplateRevision',
  ]) assert.equal(schemas[name].additionalProperties, false, `${name} rejects undeclared fields`);

  assert.equal(schemas.ManagedHost.properties.display_name.maxLength, 120);
  assert.equal(schemas.ManagedHost.properties.network_addresses.maxItems, 32);
  assert.equal(schemas.ManagedHost.properties.labels.maxProperties, 32);
  assert.equal(schemas.ManagedHost.properties.labels.additionalProperties.maxLength, 128);
  assert.equal(schemas.DiscoveryCandidate.properties.evidence_summary.maxItems, 32);
  const evidence = resolvedSchema(document, schemas.DiscoveryCandidate.properties.evidence_summary.items);
  assert.equal(evidence.additionalProperties, false);
  assert.deepEqual(resolvedSchema(document, evidence.properties.kind).enum, [
    'process_name', 'executable_path', 'systemd_unit', 'listen_endpoint', 'unix_socket',
    'container_image', 'container_label', 'container_port', 'version_hint',
  ]);
  assert.equal(evidence.properties.value.maxLength, 256);
  assert.equal(schemas.ManagedDatabaseInstance.properties.capabilities.maxItems, 64);
  assert.equal(schemas.PluginDefinition.properties.capabilities.maxItems, 64);
  assert.equal(schemas.PluginVersion.properties.platforms.maxItems, 16);
  assert.equal(schemas.PluginAssignment.properties.rollout_percentage.maximum, 100);
  assert.ok(schemas.PluginObservedState.required.includes('circuit_state'));
  assert.equal(schemas.MetricTemplateRevision.properties.timeout_seconds.maximum, 30);
  assert.equal(schemas.MetricTemplateRevision.properties.max_rows.maximum, 100);
  assert.equal(schemas.MetricTemplateRevision.properties.max_columns.maximum, 32);
  assert.equal(schemas.MetricTemplateRevision.properties.collection_interval_seconds.minimum, 10);
  assert.equal(schemas.MetricTemplateRevision.properties.collection_interval_seconds.maximum, 86400);
  assert.equal(schemas.MetricTemplateRevision.properties.label_mappings.maxItems, 16);
  assert.equal(resolvedSchema(document, schemas.MetricTemplateRevision.properties.label_mappings.items).properties.label.maxLength, 128);

  assert.deepEqual(schemas.MetricQueryKind.enum, ['sql']);
  assert.ok(schemas.MetricTemplateRevision.required.includes('query_kind'));
  assert.equal(schemas.MetricTemplateRevision.properties.read_only_statement, undefined, 'public revision DTO never returns query text');
  assert.ok(schemas.CreateMetricTemplateRevisionRequest.required.includes('query_kind'));
  assert.ok(schemas.CreateMetricTemplateRevisionRequest.required.includes('read_only_statement'));
  assert.equal(schemas.CreateMetricTemplateRevisionRequest.properties.structured_query, undefined, 'request has no unbounded structured query');

  const roots = [
    'ManagedHost', 'DiscoveryCandidate', 'AcceptDiscoveryCandidateRequest', 'ManagedDatabaseInstance',
    'UpdateDatabaseInstanceRequest', 'PluginVersion', 'PluginAssignment', 'PluginObservedState',
    'MetricTemplateRevision', 'CreateMetricTemplateRevisionRequest',
  ];
  for (const name of roots) {
    visitResolvedSchema(document, schemas[name], name, (schema, path) => {
      if (typeof schema.additionalProperties === 'object') {
        assert.ok(schema.propertyNames, `${path} bounds map property names`);
        assert.ok(schema.propertyNames.maxLength, `${path} bounds map property-name length`);
      }
      if (schema.type === 'array') assert.ok(schema.maxItems, `${path} bounds array length`);
    });
  }

  const forbiddenResponseField = /^(?:password|secret|secret_bytes|access_token|private_key|download_url|signed_url|storage_path)$/;
  for (const name of roots) {
    visitResolvedSchema(document, schemas[name], name, (schema, path) => {
      for (const field of Object.keys(schema.properties ?? {})) {
        assert.doesNotMatch(field, forbiddenResponseField, `${path}.${field} is not a secret-bearing REST field`);
      }
    });
  }
});

test('agent commands and leases are typed without arbitrary execution or persisted lease payloads', async () => {
  const command = await readFile(join(repoRoot, 'contracts/protobuf/dbpilot/agent/v1/command.proto'), 'utf8');
  const inventory = await readFile(join(repoRoot, 'contracts/protobuf/dbpilot/agent/v1/inventory.proto'), 'utf8');
  const enrollment = await readFile(join(repoRoot, 'contracts/protobuf/dbpilot/agent/v1/enrollment.proto'), 'utf8');

  for (const typedCommand of [
    'DiscoverDatabases discover_databases', 'ReconcilePlugin reconcile_plugin',
    'ApplyPluginConfiguration apply_plugin_configuration', 'ValidateDatabaseInstance validate_database_instance',
    'DrainPlugin drain_plugin', 'CollectDatabaseMetrics collect_database_metrics',
  ]) assert.match(command, new RegExp(typedCommand));
  for (const lease of [
    'CredentialLeaseRequest credential_lease_request', 'CredentialLeaseResponse credential_lease_response',
    'PluginArtifactLeaseRequest plugin_artifact_lease_request', 'PluginArtifactLeaseResponse plugin_artifact_lease_response',
    'MetricTemplateLeaseRequest metric_template_lease_request', 'MetricTemplateLeaseResponse metric_template_lease_response',
  ]) assert.match(command, new RegExp(lease));
  assert.match(command, /message CredentialLeaseRequest \{[\s\S]*?bytes request_nonce = 1;[\s\S]*?uint64 configuration_revision = 4;/);
  assert.match(command, /message CredentialLeaseResponse \{[\s\S]*?google\.protobuf\.Timestamp expires_at = 6;/);
  assert.match(command, /message PluginArtifactLeaseRequest \{[\s\S]*?bytes request_nonce = 1;[\s\S]*?uint64 operation_revision = 4;/);
  assert.match(command, /message PluginArtifactLeaseResponse \{[\s\S]*?google\.protobuf\.Timestamp expires_at = 6;/);
  assert.match(command, /message MetricTemplateLeaseRequest \{[\s\S]*?string command_id = 2;[\s\S]*?bytes query_digest = 8;/);
  assert.match(command, /message MetricTemplateLeaseResponse \{[\s\S]*?MetricTemplateDefinition definition = 11;/);
  assert.doesNotMatch(command.match(/message CommandEnvelope \{[\s\S]*?\n\}/)?.[0] ?? '', /lease_request|lease_response|download_url|http_url|url =/);
  assert.doesNotMatch(command, /shell_command|executable_path|script_body|string_command|install_hook|post_install/);
  for (const message of ['HostObservation', 'DiscoveryReport', 'PluginObservation']) {
    assert.match(inventory, new RegExp(`message ${message} \\{`));
  }
  assert.match(inventory, /message DiscoveryReport \{[\s\S]*?repeated DiscoverySourceResult source_results = 32;/);
  assert.match(inventory, /message DiscoverySourceResult \{[\s\S]*?DiscoverySource source = 1;[\s\S]*?DiscoverySourceResultStatus status = 2;[\s\S]*?DiscoverySourceReason reason = 3;/);
  assert.match(inventory, /DISCOVERY_EVIDENCE_KIND_CONTAINER_ID = 10;/);
  assert.match(enrollment, /service AgentEnrollment \{[\s\S]*?rpc Enroll\(EnrollAgentRequest\) returns \(EnrollAgentResponse\);/);
});

test('plugin and Docker discovery protobuf services expose only bounded domain operations', async () => {
  const files = await Promise.all([
    'plugin/v1/plugin.proto', 'plugin/v1/instance.proto', 'plugin/v1/metrics.proto',
    'plugin/v1/health.proto', 'discovery/v1/docker.proto',
  ].map((name) => readFile(join(repoRoot, 'contracts/protobuf/dbpilot', name), 'utf8')));
  const source = files.join('\n');

  for (const rpc of [
    'rpc Handshake(PluginHandshakeRequest) returns (PluginHandshakeResponse);',
    'rpc ApplyConfiguration(ApplyPluginConfigurationRequest) returns (ApplyPluginConfigurationResponse);',
    'rpc ValidateInstance(ValidatePluginInstanceRequest) returns (ValidatePluginInstanceResponse);',
    'rpc CollectNow(CollectPluginMetricsRequest) returns (CollectPluginMetricsResponse);',
    'rpc TrialMetricTemplate(TrialMetricTemplateRequest) returns (TrialMetricTemplateResponse);',
    'rpc StreamMetrics(StreamPluginMetricsRequest) returns (stream PluginMetricBatch);',
    'rpc AcknowledgeMetrics(AcknowledgePluginMetricsRequest) returns (AcknowledgePluginMetricsResponse);',
    'rpc GetHealth(GetPluginHealthRequest) returns (PluginHealth);',
    'rpc Shutdown(ShutdownPluginRequest) returns (ShutdownPluginResponse);',
    'rpc Snapshot(DockerSnapshotRequest) returns (DockerSnapshotResponse);',
    'rpc Watch(DockerWatchRequest) returns (stream DockerEvent);',
  ]) assert.match(source, new RegExp(rpc.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(source, /message StreamPluginMetricsRequest \{[\s\S]*?repeated PluginMetricCursor resume_cursors = 3;/);
  assert.match(source, /message AcknowledgePluginMetricsRequest \{[\s\S]*?repeated PluginMetricCursor cursors = 3;/);
  assert.match(source, /message TrialMetricTemplateRequest \{[\s\S]*?TrialMetricTemplateDefinition template = 5;/);
  assert.match(source, /message TrialMetricTemplateDefinition \{[\s\S]*?bytes read_only_statement = 5;[\s\S]*?uint32 cardinality_limit = 12;/);
  assert.match(source, /message TrialMetricTemplateResponse \{[\s\S]*?repeated PluginMetricSample candidate_metrics = 2;[\s\S]*?string error_code = 7;/);
  assert.doesNotMatch(source, /raw_rows|raw_result|driver_error|driver_message/);
  assert.doesNotMatch(source, /tenant_id|project_id|docker_socket|container_exec|shell_command|executable_path|script_body/);
});
