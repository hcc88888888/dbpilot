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

function hasTimeZone(name) {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: name });
    return true;
  } catch {
    return false;
  }
}

function validationContext(document) {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  ajv.addFormat('iana-timezone', { type: 'string', validate: hasTimeZone });
  document.$id = 'https://dbpilot.local/openapi.json';
  ajv.addSchema(document);
  return ajv;
}

function inspectionItemRequest(sourceType, sourceRule) {
  return {
    name: 'Host item',
    description: 'Host-only inspection item.',
    category: 'capacity',
    scope_type: 'host',
    source_type: sourceType,
    recommendation_template: 'Take the documented host action.',
    ...sourceRule,
  };
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
  const operations = allOperations(document);

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
  assert.equal(schemas.InspectionRun.properties.findings.maxItems, 10000);
  assert.equal(schemas.InspectionReport.properties.findings.maxItems, 10000);
  assert.ok(schemas.InspectionFinding.properties.evidence_fields);
  assert.ok(schemas.InspectionReport.properties.targets);
  assert.ok(schemas.InspectionReport.properties.references);
  assert.deepEqual(schemas.InspectionReportDownloadRequest.required, ['format']);
  assert.deepEqual(resolveComponentSchema(document, schemas.InspectionReportDownloadRequest.properties.format).enum, ['html', 'json']);
  const downloadOperation = operations.get('createInspectionReportDownload');
  assert.equal(downloadOperation.requestBody.required, true);
  assert.equal(downloadOperation.requestBody.content['application/json'].schema.$ref, '#/components/schemas/InspectionReportDownloadRequest');
  assert.match(schemas.CreateInspectionRunRequest.description, /10,000 findings/);
  assert.match(schemas.CreateInspectionRunRequest.description, /1 MiB/);
  for (const operationId of ['createInspectionRun', 'runInspectionPolicy', 'retryInspectionRun']) {
    assert.ok(operations.get(operationId).responses['422'], `${operationId} documents cross-field budget rejection`);
  }
  assert.equal(schemas.InspectionPolicy.properties.item_versions.maxItems, 200);
  assert.deepEqual(schemas.InspectionScopeType.enum, ['host']);
  assert.deepEqual(schemas.InspectionSourceType.enum, ['metric', 'metadata', 'log_summary']);
  assert.equal(schemas.InspectionProbeRule, undefined);
  assert.equal(schemas.InspectionItem.properties.database_types, undefined);
  assert.equal(schemas.CreateInspectionItemRequest.properties.database_types, undefined);
  assert.equal(schemas.InspectionEvidenceSelector.additionalProperties, false);
  assert.equal(schemas.InspectionEvidenceSelector.properties.fields.maxItems, 16);
  assert.equal(schemas.InspectionEvidenceSelector.properties.fields.uniqueItems, true);
  assert.equal(schemas.InspectionEvidenceSelector.properties.fields.items.pattern, '^[a-z][a-z0-9_.]{1,127}$');
  assert.equal(schemas.InspectionPolicy.properties.name.maxLength, 120);
  assert.equal(schemas.InspectionSchedule.properties.cron.pattern, '^(?:[^\\s]+\\s+){4}[^\\s]+$');
  assert.equal(schemas.InspectionSchedule.properties.timezone.format, 'iana-timezone');
  assert.equal(schemas.InspectionSchedule.properties.timezone.pattern, '^[A-Za-z][A-Za-z0-9._+/-]{0,127}$');

  const targetProperties = Object.keys(schemas.InspectionTarget.properties).sort();
  assert.deepEqual(targetProperties, ['agent_control_heartbeat_at', 'agent_id', 'capabilities', 'connectivity', 'display_name', 'host', 'labels']);

  const ajv = validationContext(document);
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

test('custom inspection items are host metric rules while catalog responses retain built-in source variants', async () => {
  const document = await bundleContract();
  const ajv = validationContext(document);
  const validateRequest = ajv.getSchema('https://dbpilot.local/openapi.json#/components/schemas/CreateInspectionItemRequest');
  const validateItem = ajv.getSchema('https://dbpilot.local/openapi.json#/components/schemas/InspectionItem');
  assert.ok(validateRequest);
  assert.ok(validateItem);

  const metricRule = {
    metric_rule: {
      metric_name: 'host.cpu.utilization', window: '15m', aggregation: 'avg', operator: 'gte',
      warning_threshold: 75, critical_threshold: 90,
    },
  };
  const evidenceSelector = { evidence_selector: { fields: ['host.cpu.utilization'] } };
  const metric = inspectionItemRequest('metric', metricRule);
  const metadata = inspectionItemRequest('metadata', evidenceSelector);
  const logSummary = inspectionItemRequest('log_summary', evidenceSelector);
  const customMetric = inspectionItemRequest('metric', { ...metricRule, ...evidenceSelector });

  assert.equal(validateRequest(customMetric), true, ajv.errorsText(validateRequest.errors));
  for (const invalid of [
    metric,
    inspectionItemRequest('metric', evidenceSelector),
    metadata,
    logSummary,
    inspectionItemRequest('probe', { ...metricRule, ...evidenceSelector }),
    { ...customMetric, scope_type: 'database' },
    { ...customMetric, probe_rule: { probe_template_id: 'host-shell' } },
    { ...customMetric, expression: 'SELECT * FROM sensitive_table' },
  ]) {
    assert.equal(validateRequest(invalid), false, 'custom creation accepts only host metric rules with bounded evidence');
  }

  for (const source of [metric, metadata, logSummary]) {
    const item = {
      ...source,
      id: `builtin-${source.source_type}`, version: 1, system: true, enabled: true,
      created_at: '2026-08-28T08:00:00Z', updated_at: '2026-08-28T08:00:00Z',
    };
    assert.equal(validateItem(item), true, `${source.source_type}: ${ajv.errorsText(validateItem.errors)}`);
  }
});

test('inspection schedules use TZDB-recognized IANA names and overview maps reject unknown status keys', async () => {
  const document = await bundleContract();
  const ajv = validationContext(document);
  const validateSchedule = ajv.getSchema('https://dbpilot.local/openapi.json#/components/schemas/InspectionSchedule');
  const validateOverview = ajv.getSchema('https://dbpilot.local/openapi.json#/components/schemas/InspectionOverview');
  assert.ok(validateSchedule);
  assert.ok(validateOverview);

  for (const timezone of ['UTC', 'Asia/Shanghai', 'Etc/GMT+5']) {
    assert.equal(hasTimeZone(timezone), true, `${timezone} exists in Node ICU`);
    assert.equal(validateSchedule({ cron: '0 */6 * * *', timezone }), true, ajv.errorsText(validateSchedule.errors));
  }
  assert.equal(hasTimeZone('Foo/Bar'), false, 'Foo/Bar is absent from Node ICU');
  assert.equal(validateSchedule({ cron: '0 */6 * * *', timezone: 'Foo/Bar' }), false);

  const overview = {
    target_count: 2,
    online_target_count: 2,
    latest_run_status_counts: { queued: 1, partial: 1 },
    finding_level_counts: { healthy: 4, warning: 1 },
  };
  assert.equal(validateOverview(overview), true, ajv.errorsText(validateOverview.errors));
  assert.equal(validateOverview({ ...overview, latest_run_status_counts: { queued: 1, future_status: 1 } }), false);
  assert.equal(validateOverview({ ...overview, finding_level_counts: { healthy: 1, future_level: 1 } }), false);
});
