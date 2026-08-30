import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
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

test('closed request serializers drop undeclared properties', () => {
  const serialized = api.UpdateDatabaseInstanceRequestToJSON({
    displayName: 'db',
    password: 'probe-secret',
    nestedProbe: { arbitrary: true },
  });
  assert.deepEqual(serialized, {
    display_name: 'db',
    credential_ref: undefined,
    tls_ref: undefined,
    desired_plugin_version: undefined,
    template_profile_id: undefined,
    labels: undefined,
  });
  assert.equal('password' in serialized, false);
  assert.equal('nestedProbe' in serialized, false);
});

test('closed generated request interfaces have no arbitrary index signature or spread serialization', async () => {
  for (const model of [
    'UpdateDatabaseInstanceRequest', 'UpdatePluginAssignmentRequest', 'CreateMetricTemplateRequest',
    'CreateMetricTemplateRevisionRequest', 'MetricTemplateTrialRequest', 'MetricTemplateApprovalRequest',
    'AcceptDiscoveryCandidateRequest', 'IgnoreDiscoveryCandidateRequest',
  ]) {
    const source = await readFile(`frontend/generated/api/src/models/${model}.ts`, 'utf8');
    assert.doesNotMatch(source, /\[key: string\]: any/);
    assert.doesNotMatch(source, /\.\.\.json|\.\.\.value/);
  }
});
