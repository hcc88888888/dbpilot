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

function requiredHeader(operation, name) {
  const header = operation.parameters?.find((parameter) => parameter.in === 'header' && parameter.name === name);
  assert.ok(header, `${operation.operationId} declares ${name}`);
  assert.equal(header.required, true, `${operation.operationId} requires ${name}`);
}

function resolvedSchema(document, schema) {
  if (!schema?.$ref) return schema;
  return document.components.schemas[schema.$ref.replace('#/components/schemas/', '')];
}

test('host and plugin operations expose exact permissions and concurrency headers', async () => {
  const document = await bundleContract();
  const actual = operations(document);
  const reads = new Map([
    ['listHosts', 'hosts:view'], ['getHost', 'hosts:view'],
    ['listDiscoveryCandidates', 'discovery:view'], ['getDiscoveryCandidate', 'discovery:view'],
    ['listDatabaseInstances', 'database-instances:view'], ['getDatabaseInstance', 'database-instances:view'],
    ['listPluginDefinitions', 'plugins:view'], ['listPluginVersions', 'plugins:view'],
    ['listPluginAssignments', 'plugins:view'], ['getPluginAssignment', 'plugins:view'],
    ['listMetricTemplates', 'metric-templates:view'], ['listMetricTemplateRevisions', 'metric-templates:view'],
  ]);
  const writes = new Map([
    ['rediscoverHost', 'hosts:discover'], ['decommissionHost', 'hosts:manage'],
    ['acceptDiscoveryCandidate', 'discovery:manage'], ['ignoreDiscoveryCandidate', 'discovery:manage'],
    ['updateDatabaseInstance', 'database-instances:manage'], ['testDatabaseInstanceConnection', 'database-instances:test'],
    ['createPluginVersion', 'plugins:publish'], ['approvePluginVersion', 'plugins:approve'],
    ['updatePluginAssignment', 'plugins:manage'], ['reconcilePluginAssignment', 'plugins:deploy'],
    ['createMetricTemplate', 'metric-templates:manage'], ['createMetricTemplateRevision', 'metric-templates:manage'],
    ['validateMetricTemplateRevision', 'metric-templates:manage'], ['trialMetricTemplateRevision', 'metric-templates:manage'],
    ['approveMetricTemplateRevision', 'metric-templates:approve'], ['publishMetricTemplateRevision', 'metric-templates:approve'],
  ]);

  for (const [operationId, permission] of [...reads, ...writes]) {
    assert.ok(actual.has(operationId), `${operationId} is exposed`);
    assert.equal(actual.get(operationId)['x-dbpilot-permission'], permission);
  }
  for (const operationId of writes.keys()) requiredHeader(actual.get(operationId), 'Idempotency-Key');
  for (const operationId of [
    'decommissionHost', 'updateDatabaseInstance', 'approvePluginVersion',
    'updatePluginAssignment', 'approveMetricTemplateRevision', 'publishMetricTemplateRevision',
  ]) requiredHeader(actual.get(operationId), 'If-Match');
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
  assert.equal(schemas.DiscoveryCandidate.properties.evidence_summary.items.maxLength, 256);
  assert.equal(schemas.ManagedDatabaseInstance.properties.capabilities.maxItems, 64);
  assert.equal(schemas.PluginDefinition.properties.capabilities.maxItems, 64);
  assert.equal(schemas.PluginVersion.properties.platforms.maxItems, 16);
  assert.equal(schemas.PluginAssignment.properties.rollout_percentage.maximum, 100);
  assert.equal(schemas.MetricTemplateRevision.properties.timeout_seconds.maximum, 30);
  assert.equal(schemas.MetricTemplateRevision.properties.max_rows.maximum, 100);
  assert.equal(schemas.MetricTemplateRevision.properties.max_columns.maximum, 32);
  assert.equal(schemas.MetricTemplateRevision.properties.collection_interval_seconds.minimum, 10);
  assert.equal(schemas.MetricTemplateRevision.properties.collection_interval_seconds.maximum, 86400);
  assert.equal(schemas.MetricTemplateRevision.properties.label_mappings.maxItems, 16);
  assert.equal(resolvedSchema(document, schemas.MetricTemplateRevision.properties.label_mappings.items).properties.label.maxLength, 128);

  const forbiddenResponseFields = new Set([
    'password', 'secret', 'secret_bytes', 'access_token', 'private_key', 'download_url', 'signed_url', 'storage_path',
  ]);
  for (const [name, schema] of Object.entries(schemas)) {
    if (!schema.properties) continue;
    for (const field of Object.keys(schema.properties)) {
      assert.equal(forbiddenResponseFields.has(field), false, `${name}.${field} is not a REST response field`);
    }
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
  ]) assert.match(command, new RegExp(lease));
  assert.match(command, /message CredentialLeaseRequest \{[\s\S]*?bytes request_nonce = 1;[\s\S]*?uint64 configuration_revision = 4;/);
  assert.match(command, /message CredentialLeaseResponse \{[\s\S]*?google\.protobuf\.Timestamp expires_at = 6;/);
  assert.match(command, /message PluginArtifactLeaseRequest \{[\s\S]*?bytes request_nonce = 1;[\s\S]*?uint64 operation_revision = 4;/);
  assert.match(command, /message PluginArtifactLeaseResponse \{[\s\S]*?google\.protobuf\.Timestamp expires_at = 6;/);
  assert.doesNotMatch(command.match(/message CommandEnvelope \{[\s\S]*?\n\}/)?.[0] ?? '', /lease_request|lease_response|download_url|http_url|url =/);
  assert.doesNotMatch(command, /shell_command|executable_path|script_body|string_command|install_hook|post_install/);
  for (const message of ['HostObservation', 'DiscoveryReport', 'PluginObservation']) {
    assert.match(inventory, new RegExp(`message ${message} \\{`));
  }
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
    'rpc StreamMetrics(StreamPluginMetricsRequest) returns (stream PluginMetricBatch);',
    'rpc GetHealth(GetPluginHealthRequest) returns (PluginHealth);',
    'rpc Shutdown(ShutdownPluginRequest) returns (ShutdownPluginResponse);',
    'rpc Snapshot(DockerSnapshotRequest) returns (DockerSnapshotResponse);',
    'rpc Watch(DockerWatchRequest) returns (stream DockerEvent);',
  ]) assert.match(source, new RegExp(rpc.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.doesNotMatch(source, /tenant_id|project_id|docker_socket|container_exec|shell_command|executable_path|script_body/);
});
