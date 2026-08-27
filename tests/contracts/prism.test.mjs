import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const composeFile = fileURLToPath(new URL('../../deploy/contracts/prism.compose.yaml', import.meta.url));
const mockBaseUrl = process.env.DBPILOT_CONTRACT_MOCK_URL ?? 'http://localhost:4010';
const integrationEnabled = process.env.DBPILOT_PRISM_INTEGRATION === '1';

if (integrationEnabled) {
  test.after(async () => {
    try {
      await execFileAsync('docker', ['compose', '-p', 'dbpilot-contracts', '-f', composeFile, 'down', '--volumes', '--remove-orphans']);
    }
    catch {
      // Cleanup must not mask the contract assertion that caused the test to fail.
    }
  });
}

test('Prism serves the documented capabilities example', {
  skip: integrationEnabled ? false : 'set DBPILOT_PRISM_INTEGRATION=1 to run Prism integration',
}, async () => {
  const response = await fetch(`${mockBaseUrl}/api/v1/tenants/demo/projects/demo/capabilities`, {
    headers: { Authorization: 'Bearer prism-test-token' },
  });
  assert.equal(response.status, 200);

  const body = await response.json();
  assert.ok(Array.isArray(body.capabilities));
  assert.ok(body.capabilities.length > 0);
  for (const capability of body.capabilities) {
    assert.equal(typeof capability.name, 'string');
    assert.equal(typeof capability.enabled, 'boolean');
    assert.ok(capability.reason_code === null || typeof capability.reason_code === 'string');
    assert.ok(Array.isArray(capability.database_types));
    assert.ok(capability.database_types.every((value) => typeof value === 'string'));
    assert.ok(Array.isArray(capability.agent_capabilities));
    assert.ok(capability.agent_capabilities.every((value) => typeof value === 'string'));
    assert.equal(typeof capability.required_permission, 'string');
  }
});
