import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv from '@redocly/ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const redoclyCli = join(repoRoot, 'node_modules', '@redocly', 'cli', 'bin', 'cli.js');

async function bundleContract() {
  const bundleDirectory = await mkdtemp(join(tmpdir(), 'dbpilot-inspection-openapi-'));
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
    if (result.error) throw result.error;
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(await readFile(bundlePath, 'utf8'));
  } finally {
    await rm(bundleDirectory, { recursive: true, force: true });
  }
}

function allOperations(document) {
  return new Map(Object.values(document.paths).flatMap((pathItem) =>
    Object.entries(pathItem)
      .filter(([method]) => ['get', 'post', 'patch'].includes(method))
      .map(([, operation]) => [operation.operationId, operation]),
  ));
}

function assertRequiredHeader(operation, name) {
  const parameter = operation.parameters?.find((item) => item.in === 'header' && item.name === name);
  assert.ok(parameter, `${operation.operationId} declares ${name}`);
  assert.equal(parameter.required, true, `${operation.operationId} requires ${name}`);
}

function resolveComponentSchema(document, schema) {
  if (!schema.$ref) return schema;
  const name = schema.$ref.replace('#/components/schemas/', '');
  return document.components.schemas[name];
}

test('inspection operations protect reads and writes with the documented permissions and concurrency headers', async () => {
  const document = await bundleContract();
  const operations = allOperations(document);
  const expectedWrites = new Map([
    ['createInspectionItem', 'inspection:manage'],
    ['createInspectionPolicy', 'inspection:manage'],
    ['updateInspectionPolicy', 'inspection:manage'],
    ['runInspectionPolicy', 'inspection:execute'],
    ['createInspectionRun', 'inspection:execute'],
    ['cancelInspectionRun', 'inspection:execute'],
    ['retryInspectionRun', 'inspection:execute'],
    ['createInspectionReportDownload', 'inspection:view'],
  ]);
  const expectedReads = [
    'getInspectionOverview',
    'listInspectionTargets',
    'listInspectionItems',
    'listInspectionPolicies',
    'getInspectionPolicy',
    'listInspectionRuns',
    'getInspectionRun',
    'listInspectionReports',
    'getInspectionReport',
  ];

  for (const [operationId, permission] of expectedWrites) {
    const operation = operations.get(operationId);
    assert.ok(operation, `${operationId} is exposed`);
    assert.equal(operation['x-dbpilot-permission'], permission);
    assertRequiredHeader(operation, 'Idempotency-Key');
  }
  assertRequiredHeader(operations.get('updateInspectionPolicy'), 'If-Match');

  for (const operationId of expectedReads) {
    const operation = operations.get(operationId);
    assert.ok(operation, `${operationId} is exposed`);
    assert.equal(operation['x-dbpilot-permission'], 'inspection:view');
  }
});

test('inspection DTOs bound host data, status vocabularies, and public examples', async () => {
  const document = await bundleContract();
  const schemas = document.components.schemas;

  assert.deepEqual(resolveComponentSchema(document, schemas.InspectionFinding.properties.level).enum, [
    'healthy', 'warning', 'critical', 'unsupported', 'missing_data',
  ]);
  assert.deepEqual(resolveComponentSchema(document, schemas.InspectionRun.properties.status).enum, [
    'queued', 'collecting', 'evaluating', 'generating_report', 'completed', 'partial', 'failed', 'cancelled',
  ]);
  assert.equal(schemas.InspectionMetricRule.additionalProperties, false);
  assert.equal(schemas.InspectionMetricRule.properties.metric_name.pattern, '^[a-z][a-z0-9_.]{1,127}$');
  assert.equal(schemas.InspectionMetricRule.properties.labels.maxProperties, 16);
  assert.equal(schemas.InspectionMetricRule.properties.labels.additionalProperties.maxLength, 128);
  assert.deepEqual(resolveComponentSchema(document, schemas.InspectionMetricRule.properties.window).enum, ['5m', '15m', '1h']);
  assert.deepEqual(resolveComponentSchema(document, schemas.InspectionMetricRule.properties.aggregation).enum, ['latest', 'avg', 'max', 'min']);
  assert.deepEqual(resolveComponentSchema(document, schemas.InspectionMetricRule.properties.operator).enum, ['gt', 'gte', 'lt', 'lte']);
  assert.equal(schemas.CreateInspectionRunRequest.properties.target_ids.maxItems, 10000);
  assert.equal(schemas.InspectionPolicy.properties.item_versions.maxItems, 200);
  assert.equal(schemas.InspectionItem.properties.evidence_selector.maxLength, 65536);
  assert.equal(schemas.InspectionPolicy.properties.name.maxLength, 120);
  assert.equal(schemas.InspectionSchedule.properties.cron.pattern, '^(?:[^\\s]+\\s+){4}[^\\s]+$');
  assert.equal(schemas.InspectionSchedule.properties.timezone.format, 'iana-timezone');

  const targetProperties = Object.keys(schemas.InspectionTarget.properties).sort();
  assert.deepEqual(targetProperties, ['agent_id', 'capabilities', 'connectivity', 'display_name', 'host', 'labels']);

  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  ajv.addFormat('iana-timezone', /^[A-Za-z_]+(?:\/[A-Za-z_+-]+)+$/);
  document.$id = 'https://dbpilot.local/openapi.json';
  ajv.addSchema(document);
  const examples = [
    ['items.json', 'InspectionItemPage'],
    ['policy.json', 'InspectionPolicy'],
    ['run.json', 'InspectionRun'],
    ['report.json', 'InspectionReport'],
  ];
  for (const [fileName, schemaName] of examples) {
    const value = JSON.parse(await readFile(join(repoRoot, 'contracts', 'examples', 'inspection', fileName), 'utf8'));
    const validate = ajv.getSchema(`https://dbpilot.local/openapi.json#/components/schemas/${schemaName}`);
    assert.ok(validate, `${schemaName} schema is available for ${fileName}`);
    assert.equal(validate(value), true, `${fileName}: ${ajv.errorsText(validate.errors)}`);
  }
});
