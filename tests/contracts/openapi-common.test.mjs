import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const redoclyCli = join(repoRoot, 'node_modules', '@redocly', 'cli', 'bin', 'cli.js');
const utcPattern = '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,9})?Z$';
const utcRegex = new RegExp(utcPattern);

const expectedOperations = [
  ['/jobs/{job_id}', 'get', 'getJob', 'platform.jobs.read'],
  ['/jobs/{job_id}/actions/cancel', 'post', 'cancelJob', 'platform.jobs.cancel'],
  ['/artifacts/{artifact_id}', 'get', 'getArtifact', 'platform.artifacts.read'],
  ['/artifacts/{artifact_id}/actions/download', 'post', 'createArtifactDownload', 'platform.artifacts.download'],
  ['/audit-events', 'get', 'listAuditEvents', 'platform.audit.read'],
  ['/capabilities', 'get', 'getCapabilities', 'platform.capabilities.read'],
  ['/inspection-overview', 'get', 'getInspectionOverview', 'inspection:view'],
  ['/inspection-targets', 'get', 'listInspectionTargets', 'inspection:view'],
  ['/inspection-items', 'get', 'listInspectionItems', 'inspection:view'],
  ['/inspection-items', 'post', 'createInspectionItem', 'inspection:manage'],
  ['/inspection-policies', 'get', 'listInspectionPolicies', 'inspection:view'],
  ['/inspection-policies', 'post', 'createInspectionPolicy', 'inspection:manage'],
  ['/inspection-policies/{policy_id}', 'get', 'getInspectionPolicy', 'inspection:view'],
  ['/inspection-policies/{policy_id}', 'patch', 'updateInspectionPolicy', 'inspection:manage'],
  ['/inspection-policies/{policy_id}/run', 'post', 'runInspectionPolicy', 'inspection:execute'],
  ['/inspection-runs', 'get', 'listInspectionRuns', 'inspection:view'],
  ['/inspection-runs', 'post', 'createInspectionRun', 'inspection:execute'],
  ['/inspection-runs/{run_id}', 'get', 'getInspectionRun', 'inspection:view'],
  ['/inspection-runs/{run_id}/cancel', 'post', 'cancelInspectionRun', 'inspection:execute'],
  ['/inspection-runs/{run_id}/retry', 'post', 'retryInspectionRun', 'inspection:execute'],
  ['/inspection-reports', 'get', 'listInspectionReports', 'inspection:view'],
  ['/inspection-reports/{report_id}', 'get', 'getInspectionReport', 'inspection:view'],
  ['/inspection-reports/{report_id}/download', 'post', 'createInspectionReportDownload', 'inspection:view'],
];

async function bundleContract() {
  const bundleDirectory = await mkdtemp(join(tmpdir(), 'dbpilot-openapi-bundle-'));
  const bundlePath = join(bundleDirectory, 'dbpilot-api.json');

  try {
    const result = spawnSync(process.execPath, [
      redoclyCli,
      'bundle',
      'contracts/openapi/dbpilot-api.yaml',
      '--ext',
      'json',
      '--output',
      bundlePath,
    ], { cwd: repoRoot, encoding: 'utf8' });

    if (result.error) {
      throw result.error;
    }
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(await readFile(bundlePath, 'utf8'));
  } finally {
    await rm(bundleDirectory, { recursive: true, force: true });
  }
}

function resolveLocalReference(document, value) {
  if (!value.$ref) {
    return value;
  }

  assert.match(value.$ref, /^#\//, `expected bundled local reference, received ${value.$ref}`);
  return value.$ref.slice(2).split('/').reduce((current, segment) => current[segment], document);
}

function assertUtcTimestampReference(schema, nullable = false) {
  if (nullable) {
    assert.deepEqual(schema, {
      oneOf: [
        { $ref: '#/components/schemas/UtcTimestamp' },
        { type: 'null' },
      ],
    });
    return;
  }

  assert.deepEqual(schema, { $ref: '#/components/schemas/UtcTimestamp' });
}

function collectExampleTimestamps(value, values = []) {
  if (Array.isArray(value)) {
    for (const item of value) {
      collectExampleTimestamps(item, values);
    }
  } else if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      if (key.endsWith('_at') && child !== null) {
        values.push(child);
      }
      collectExampleTimestamps(child, values);
    }
  }
  return values;
}

test('bundled contract structurally defines the common platform contract', async () => {
  const document = await bundleContract();

  assert.deepEqual(document.servers.map((server) => server.url), [
    '/api/v1/tenants/{tenant_id}/projects/{project_id}',
  ]);

  const operations = Object.entries(document.paths).flatMap(([path, pathItem]) =>
    Object.entries(pathItem)
      .filter(([method]) => ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace'].includes(method))
      .map(([method, operation]) => ({ path, method, operation })),
  );
  assert.deepEqual(
    operations.map(({ path, method, operation }) => [
      path,
      method,
      operation.operationId,
      operation['x-dbpilot-permission'],
    ]),
    expectedOperations,
  );
  for (const { operation } of operations) {
    assert.equal(Object.keys(operation).filter((key) => key === 'x-dbpilot-permission').length, 1);
  }

  assert.deepEqual(document.components.schemas.JobStatus.enum, [
    'queued', 'dispatched', 'running', 'succeeded', 'failed', 'cancelling', 'cancelled', 'timed_out',
  ]);
  assert.deepEqual(document.components.schemas.JobOutcome.enum, ['complete', 'partial', 'none']);
  assert.equal(document.components.schemas.UtcTimestamp.type, 'string');
  assert.equal(document.components.schemas.UtcTimestamp.format, 'date-time');
  assert.match(document.components.schemas.UtcTimestamp.description, /UTC/);
  assert.equal(document.components.schemas.UtcTimestamp.pattern, utcPattern);

  const { Job, Artifact, DownloadDescriptor, AuditEvent } = document.components.schemas;
  assertUtcTimestampReference(Job.properties.created_at);
  for (const field of ['dispatched_at', 'started_at', 'finished_at', 'timeout_at']) {
    assertUtcTimestampReference(Job.properties[field], true);
  }
  assertUtcTimestampReference(Artifact.properties.created_at);
  assertUtcTimestampReference(Artifact.properties.expires_at, true);
  assertUtcTimestampReference(DownloadDescriptor.properties.expires_at);
  assertUtcTimestampReference(AuditEvent.properties.occurred_at);
	assert.ok(AuditEvent.required.includes('result'));
	assert.equal(AuditEvent.properties.result.minLength, 1);
	assert.deepEqual(AuditEvent.properties.command_id, { $ref: '#/components/schemas/CommandId' });
	assert.equal(document.paths['/audit-events'].get.parameters.find((parameter) => parameter.name === 'limit').schema.maximum, 100);
	assert.equal(document.components.schemas.ArtifactId.minLength, 1);
	assert.equal(document.components.schemas.ArtifactId.pattern, undefined);
	assert.equal(document.components.schemas.ArtifactId.maxLength, undefined);

  const cancel = document.paths['/jobs/{job_id}/actions/cancel'].post;
  for (const header of ['Idempotency-Key', 'If-Match']) {
    const parameter = cancel.parameters.find((candidate) => candidate.in === 'header' && candidate.name === header);
    assert.ok(parameter, `${header} is required by job cancellation`);
    assert.equal(parameter.required, true);
  }
  assert.ok(cancel.responses['202']);
  assert.ok(cancel.responses['412']);

  for (const { operation } of operations) {
    assert.ok(operation.responses['400'], `${operation.operationId} documents request validation failures`);
    const methodNotAllowed = resolveLocalReference(document, operation.responses['405']);
    assert.equal(methodNotAllowed.headers.Allow.required, true, `${operation.operationId} 405 requires Allow`);
    assert.equal(methodNotAllowed.headers.Allow.schema.type, 'string');
  }
  assert.ok(document.paths['/artifacts/{artifact_id}/actions/download'].post.responses['409']);

  for (const { operation } of operations) {
    for (const [status, response] of Object.entries(operation.responses)) {
      if (Number(status) >= 400) {
        const problemResponse = resolveLocalReference(document, response);
        assert.ok(problemResponse.content['application/problem+json'], `${operation.operationId} ${status}`);
        assert.deepEqual(problemResponse.content['application/problem+json'].schema, {
          $ref: '#/components/schemas/Problem',
        });
      }
    }
  }

  const download = document.paths['/artifacts/{artifact_id}/actions/download'].post.responses['200'];
  assert.deepEqual(Object.keys(download.content), ['application/json']);
  assert.deepEqual(download.content['application/json'].schema, {
    $ref: '#/components/schemas/DownloadDescriptor',
  });

  const examples = await Promise.all([
    'job-running.json',
    'problem-validation.json',
    'capabilities.json',
  ].map(async (name) => JSON.parse(await readFile(join(repoRoot, 'contracts', 'examples', 'platform', name), 'utf8'))));
  for (const timestamp of examples.flatMap((example) => collectExampleTimestamps(example))) {
    assert.match(timestamp, utcRegex);
  }
});
