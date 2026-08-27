import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('root contract exposes common platform operations and permission metadata', async () => {
  const source = (await Promise.all([
    readFile('contracts/openapi/dbpilot-api.yaml', 'utf8'),
    readFile('contracts/openapi/modules/platform.yaml', 'utf8'),
  ])).join('\n');
  for (const value of ['openapi: 3.1.0', 'operationId: getJob', 'operationId: cancelJob',
    'operationId: getCapabilities', 'application/problem+json', 'x-dbpilot-permission']) {
    assert.match(source, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});
