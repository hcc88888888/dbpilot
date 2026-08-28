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
  assert.match(files, /message CommandCancellation \{[\s\S]*?bytes execution_token = 3;[\s\S]*?uint64 lease_revision = 4;[\s\S]*?\}/);
  assert.doesNotMatch(files, /shell_command/);
});
