import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const prismTest = fileURLToPath(new URL('./prism.test.mjs', import.meta.url));

test('Prism integration is skipped unless explicitly enabled', async () => {
  const environment = { ...process.env };
  delete environment.DBPILOT_PRISM_INTEGRATION;
  delete environment.NODE_TEST_CONTEXT;

  const { stdout, stderr } = await execFileAsync(process.execPath, ['--test', prismTest], { env: environment });

  assert.match(`${stdout}${stderr}`, /skipped 1/);
});
