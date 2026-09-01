import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('Agent v1 exposes typed commands and forbids arbitrary shell', async () => {
  const names = ['telemetry.proto', 'policy.proto', 'command.proto', 'inventory.proto'];
  const files = (await Promise.all(names.map((name) =>
    readFile(`contracts/protobuf/dbpilot/agent/v1/${name}`, 'utf8')))).join('\n');
  for (const required of ['service AgentControl',
    'rpc Connect(stream AgentMessage) returns (stream ServerMessage)',
    'oneof command', 'CollectNow', 'InspectInstance', 'ExecuteSQL',
    'ExecuteRegisteredProcess', 'CollectDiagnostic', 'CommandPrepared',
    'command_prepared = 26', 'CommandStart', 'command_start = 26',
    'bytes execution_token', 'uint64 lease_revision', 'bytes result_digest',
    'CommandResultAcknowledgement', 'command_result_acknowledgement = 25',
    'service TelemetryIngest']) {
    assert.match(files, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
  assert.match(files, /message CommandProgress \{[\s\S]*?bytes execution_token = 5;[\s\S]*?uint64 lease_revision = 6;[\s\S]*?\}/);
  assert.match(files, /message CommandResult \{[\s\S]*?bytes execution_token = 6;[\s\S]*?uint64 lease_revision = 7;[\s\S]*?\}/);
  assert.match(files, /message CommandResult \{[\s\S]*?MetricTemplateTrialResult metric_template_trial_result = 8;[\s\S]*?\}/);
  assert.match(files, /message CollectDatabaseMetrics \{[\s\S]*?uint64 operation_revision = 5;[\s\S]*?repeated MetricTemplateCommandReference template_revisions = 6;[\s\S]*?bool trial = 7;[\s\S]*?\}/);
  assert.match(files, /message ReconcilePlugin \{[\s\S]*?repeated MetricTemplateCommandReference template_revisions = 13;[\s\S]*?repeated PluginInstanceTemplateReferences instance_template_revisions = 14;[\s\S]*?\}/);
  assert.match(files, /message MetricTemplateCommandReference \{[\s\S]*?string template_id = 1;[\s\S]*?string revision_id = 2;[\s\S]*?bytes query_digest = 3;[\s\S]*?\}/);
  assert.match(files, /MetricTemplateLeaseRequest metric_template_lease_request = 32;/);
  assert.match(files, /MetricTemplateLeaseResponse metric_template_lease_response = 29;/);
  assert.match(files, /message MetricTemplateLeaseRequest \{[\s\S]*?string command_id = 2;[\s\S]*?string revision_id = 7;[\s\S]*?bytes query_digest = 8;[\s\S]*?string template_id = 9;[\s\S]*?\}/);
  assert.match(files, /message MetricTemplateDefinition \{[\s\S]*?bytes read_only_statement = 3;[\s\S]*?uint32 timeout_seconds = 5;[\s\S]*?uint32 cardinality_limit = 8;[\s\S]*?\}/);
  assert.match(files, /message CommandCancellation \{[\s\S]*?bytes execution_token = 3;[\s\S]*?uint64 lease_revision = 4;[\s\S]*?\}/);
  assert.doesNotMatch(files, /shell_command/);
  const commandEnvelope = files.match(/message CommandEnvelope \{[\s\S]*?\n\}/)?.[0] ?? '';
  assert.doesNotMatch(commandEnvelope, /read_only_statement|MetricTemplateDefinition|metric_template_lease/);
});
