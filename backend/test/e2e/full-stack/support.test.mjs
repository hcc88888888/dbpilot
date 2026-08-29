import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import playwrightConfig from './playwright.config.mjs';
import {
  assertNoSecretExposure,
  browserPhaseState,
  createFailureArtifacts,
  findingEvidenceIsComplete,
  inspectionRunDiagnostic,
  renderedFindingMatches,
  verifyArtifactDownload,
} from './support.mjs';

test('inspection timeout diagnostic retains only bounded state and counts', () => {
  const diagnostic = inspectionRunDiagnostic({
    status: 'collecting', target_count: 2, completed_target_count: 0, failed_target_count: 0,
    targets: [
      { status: 'pending', error_code: '', command_id: 'command-secret-id' },
      { status: 'failed', error_code: 'agent_offline', agent_id: 'agent-secret-id' },
    ],
    id: 'run-secret-id', job_id: 'job-secret-id', initiated_by: 'operator-secret-id',
  }, {
    status: 'running', progress: { total_targets: 2, completed_targets: 1, failed_targets: 0, skipped_targets: 0 },
    target_results: [{ status: 'succeeded', target_id: 'agent-secret-id' }], id: 'job-secret-id',
  }, {
    findings: [
      { level: 'healthy', item_id: 'host.cpu.utilization' },
      { level: 'missing_data', item_id: 'host.time.synchronization' },
      { level: 'missing_data', item_id: 'credential=do-not-retain' },
    ],
  });
  assert.equal(diagnostic, 'run_status=collecting target_count=2 completed=0 failed=0 target_states=failed:1,pending:1 error_codes=agent_offline:1 job_status=running job_progress=1/2 job_failed=0 job_skipped=0 job_target_states=succeeded:1 finding_levels=healthy:1,missing_data:2 missing_items=host.time.synchronization,unknown');
  assert.equal(diagnostic.includes('secret-id'), false);
});

test('browser phase state contains only non-secret scope and durable workflow identities', () => {
  const state = browserPhaseState({
    tenantID: 'tenant-acceptance', projectID: 'project-acceptance', onlineAgentID: 'agent-online', offlineAgentID: 'agent-offline',
    policy: { id: 'policy-1' },
    run: { id: 'run-1', report_id: 'report-1', target_count: 2 },
    report: { id: 'report-1', artifacts: [{ artifact_id: 'artifact-html' }, { artifact_id: 'artifact-json' }], references: { job_id: 'job-1', audit_correlation: 'correlation-1', commands: [
      { target_id: 'agent-online', command_id: 'command-online' },
      { target_id: 'agent-offline', command_id: 'command-offline' },
    ] } },
  });
  assert.deepEqual(state, {
    version: 1, tenant_id: 'tenant-acceptance', project_id: 'project-acceptance', online_agent_id: 'agent-online', offline_agent_id: 'agent-offline', policy_id: 'policy-1',
    run_id: 'run-1', job_id: 'job-1', report_id: 'report-1', online_command_id: 'command-online',
    offline_command_id: 'command-offline', journal_command_id: 'command-online', audit_correlation: 'correlation-1',
    target_count: 2, artifact_count: 2,
  });
  assert.equal(JSON.stringify(state).includes('token'), false);
  assert.throws(() => browserPhaseState({
    tenantID: 'tenant-acceptance', projectID: 'project-acceptance', onlineAgentID: 'agent-online', offlineAgentID: 'agent-offline',
    policy: { id: 'policy-1' }, run: { id: 'run-1', report_id: 'report-1', target_count: 2 }, report: { id: 'report-1', artifacts: [{}, {}], references: { job_id: 'job-1', audit_correlation: 'correlation-1', commands: [] } },
  }), /browser phase state is invalid/);
});

test('simulated token leak reports a fixed message and redacts every retained text artifact', () => {
  const token = 'eyJhbGciOiJSUzI1NiJ9.acceptance-payload.acceptance-signature';
  let failure;
  try {
    assertNoSecretExposure({
      secrets: [token],
      body: `toast leaked ${token}`,
      url: `https://frontend.example/#${token}`,
      consoleEntries: [`Authorization: Bearer ${token}`],
    });
  } catch (error) {
    failure = error;
  }

  assert.ok(failure instanceof Error);
  assert.equal(failure.message, 'browser secret exposure detected');
  assert.equal(String(failure).includes(token), false);

  const artifacts = createFailureArtifacts({
    secrets: [token],
    html: `<html><body>${token}</body></html>`,
    consoleEntries: [`Authorization: Bearer ${token}`],
  });
  for (const retained of [artifacts.dom, artifacts.console, artifacts.screenshotMarkup]) {
    assert.equal(retained.includes(token), false);
  }
  assert.match(artifacts.dom, /\[REDACTED\]/);
  assert.match(artifacts.console, /\[REDACTED\]/);
  assert.equal(artifacts.screenshotMarkup, '<main><h1>DBPilot acceptance failed</h1><p>Sanitized diagnostics are attached.</p></main>');
});

test('Playwright automatic screenshots stay disabled for secret-safe manual capture', () => {
  assert.equal(playwrightConfig.use.screenshot, 'off');
  assert.equal(playwrightConfig.use.trace, 'off');
  assert.equal(playwrightConfig.use.video, 'off');
});

test('finding evidence requires non-empty production fields and matched rendered values', () => {
  const valid = {
    item_id: 'host.cpu.utilization',
    evidence: '{"metric":"system.cpu.utilization","value":"42.5"}',
    summary: 'CPU utilization is healthy.',
    recommendation: 'No action is required.',
    warning_threshold: 75,
    critical_threshold: 90,
  };
  assert.equal(findingEvidenceIsComplete(valid), true);
  assert.equal(renderedFindingMatches('75 90 system.cpu.utilization 42.5 CPU utilization is healthy. No action is required.', valid), true);
  assert.equal(renderedFindingMatches('75 90 CPU utilization is healthy.', valid), false);

  for (const incomplete of [
    { ...valid, evidence: '', evidence_fields: {} },
    { ...valid, summary: ' ' },
    { ...valid, recommendation: '' },
    { ...valid, critical_threshold: undefined },
  ]) assert.equal(findingEvidenceIsComplete(incomplete), false);
});

test('artifact download verifies exact HTML and JSON bytes against their metadata', () => {
  const runId = 'run-acceptance-1';
  const fixtures = [
    ['html', 'text/html; charset=utf-8', Buffer.from(`<html><body>${runId}</body></html>`, 'utf8')],
    ['json', 'application/json', Buffer.from(JSON.stringify({ run_id: runId, status: 'partial' }), 'utf8')],
  ];
  for (const [format, contentType, bytes] of fixtures) {
    const metadata = artifactMetadata(format, contentType, bytes);
    assert.doesNotThrow(() => verifyArtifactDownload({ format, bytes, responseContentType: contentType, metadata, runId }));
  }
});

test('artifact download rejects corrupt bytes and mismatched metadata with fixed diagnostics', () => {
  const runId = 'run-acceptance-1';
  const bytes = Buffer.from(JSON.stringify({ run_id: runId }), 'utf8');
  const metadata = artifactMetadata('json', 'application/json', bytes);

  assert.throws(
    () => verifyArtifactDownload({ format: 'json', bytes: Buffer.concat([bytes, Buffer.from('corrupt')]), responseContentType: 'application/json', metadata, runId }),
    (error) => error?.message === 'artifact download size mismatch' && !String(error).includes(bytes.toString('utf8')),
  );
  assert.throws(
    () => verifyArtifactDownload({ format: 'html', bytes, responseContentType: 'application/json', metadata, runId }),
    (error) => error?.message === 'artifact download format mismatch' && !String(error).includes(bytes.toString('utf8')),
  );
  assert.throws(
    () => verifyArtifactDownload({ format: 'json', bytes, responseContentType: 'text/html; charset=utf-8', metadata, runId }),
    (error) => error?.message === 'artifact download content type mismatch' && !String(error).includes(bytes.toString('utf8')),
  );
  assert.throws(
    () => verifyArtifactDownload({ format: 'json', bytes, responseContentType: 'application/json', metadata: { ...metadata, checksum: `sha256:${'0'.repeat(64)}` }, runId }),
    (error) => error?.message === 'artifact download checksum mismatch' && !String(error).includes(bytes.toString('utf8')),
  );
});

function artifactMetadata(format, contentType, bytes) {
  return {
    id: `artifact-${format}`,
    kind: `inspection-report-${format}`,
    content_type: contentType,
    size_bytes: bytes.length,
    checksum: `sha256:${createHash('sha256').update(bytes).digest('hex')}`,
  };
}
