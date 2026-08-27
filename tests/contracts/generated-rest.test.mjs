import test from 'node:test';
import assert from 'node:assert/strict';
import * as api from '../../frontend/generated/api/dist/index.js';

test('generated browser client exposes the platform API', () => {
  assert.equal(typeof api.PlatformApi, 'function');
  assert.equal(typeof api.Configuration, 'function');
});
