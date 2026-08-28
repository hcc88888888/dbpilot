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
    'ExecuteRegisteredProcess', 'CollectDiagnostic', 'CommandResultAcknowledgement',
    'command_result_acknowledgement = 25', 'service TelemetryIngest']) {
    assert.match(files, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
  assert.doesNotMatch(files, /shell_command/);
});
