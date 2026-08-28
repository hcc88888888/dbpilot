import test from 'node:test';
import assert from 'node:assert/strict';
import * as api from '../../frontend/generated/api/dist/index.js';

test('generated browser client exposes the platform API', () => {
  assert.equal(typeof api.PlatformApi, 'function');
  assert.equal(typeof api.Configuration, 'function');
});

test('generated enum deserialization maps unknown wire values to the open enum sentinel', () => {
  assert.equal(api.JobStatusFromJSON('future_status'), api.JobStatus.UnknownDefaultOpenApi);
  assert.equal(api.JobStatusFromJSON('running'), api.JobStatus.Running);
  assert.equal(api.JobOutcomeFromJSON('future_outcome'), api.JobOutcome.UnknownDefaultOpenApi);
  assert.equal(api.JobOutcomeFromJSON('complete'), api.JobOutcome.Complete);
});
