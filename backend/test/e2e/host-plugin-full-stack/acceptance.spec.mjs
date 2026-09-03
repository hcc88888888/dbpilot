import { test, expect } from '@playwright/test';
import { chmod, readFile, rename, writeFile } from 'node:fs/promises';
import { buildPluginPackage } from './plugin-package.mjs';

const required = [
  'FRONTEND_URL', 'OIDC_URL', 'OIDC_CREDENTIAL_FILE', 'PLUGIN_PUBLISHER_KEY_FILE',
  'PLUGIN_BINARY_FILE', 'PLUGIN_ARM64_BINARY_FILE', 'TENANT_ID', 'PROJECT_ID', 'HOST_ID', 'AGENT_ID',
  'ENROLLMENT_INBOX_DIR', 'ACCEPTANCE_STATE_FILE', 'DBPILOT_ACCEPTANCE_PHASE',
];
const env = Object.fromEntries(required.map((name) => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(name + ' is required');
  return [name, value];
}));
const scopePath = '/api/v1/tenants/' + encodeURIComponent(env.TENANT_ID) + '/projects/' + encodeURIComponent(env.PROJECT_ID);
const phase = env.DBPILOT_ACCEPTANCE_PHASE;
const restartBoundaryUTC = process.env.RESTART_BOUNDARY_UTC?.trim() ?? '';
const mysqlMetrics = ['mysql.connections.current', 'mysql.queries.total', 'mysql.threads.running', 'mysql.up', 'mysql.uptime.seconds'];
const failureCanaries = {
  sql: 'DBPILOT_CANARY_SQL_7f30e2',
  packageBytes: 'DBPILOT_CANARY_PACKAGE_BYTES_7f30e2',
  trialRow: 'DBPILOT_CANARY_TRIAL_ROW_7f30e2',
  rawInspect: 'DBPILOT_CANARY_RAW_INSPECT_7f30e2',
  nonPemKey: 'DBPILOT_CANARY_NON_PEM_PRIVATE_KEY_7f30e2',
};

test.describe.configure({ mode: 'serial' });

test('create one-time enrollment without retaining its token', async ({ request }) => {
  test.skip(phase !== 'enrollment');
  const token = await issueToken(request, 'valid');
  const response = await api(request, token, '/host-enrollments', {
    method: 'POST',
    headers: { 'Idempotency-Key': 'host-plugin-enrollment-1' },
    data: { host_id: env.HOST_ID, agent_id: env.AGENT_ID, display_name: 'Kylin host plugin acceptance', labels: { environment: 'acceptance' }, expires_in_seconds: 1800 },
    status: 201,
  });
  expect(response.body.enrollment_token).toMatch(/^[A-Za-z0-9_-]{43}$/);
  const tokenPath = env.ENROLLMENT_INBOX_DIR + '/enrollment-token';
  await writeFile(tokenPath + '.tmp', response.body.enrollment_token + '\n', { mode: 0o600 });
  await rename(tokenPath + '.tmp', tokenPath);
  await chmod(tokenPath, 0o600);
  await saveState({ enrollment_revision: response.body.enrollment_revision });
});

test('publish signed plugin, discover two internal-only MySQLs, and converge one process', async ({ request }) => {
  test.skip(phase !== 'platform');
  await markDiagnosticStage('platform-signature');
  const token = await issueToken(request, 'valid');
  const binary = await readFile(env.PLUGIN_BINARY_FILE);
  const arm64Binary = await readFile(env.PLUGIN_ARM64_BINARY_FILE);
  const key = await readFile(env.PLUGIN_PUBLISHER_KEY_FILE);
  const tampered = buildPluginPackage(binary, key, { version: '0.9.0', tamperSignature: true });
  const signatureProblem = await api(request, token, '/plugin-versions', { method: 'POST', headers: uploadHeaders('tampered-1', tampered), body: tampered, status: 422 });
  expect(signatureProblem.body.type).toBe('https://dbpilot.local/problems/plugin_signature_rejected');
  await markDiagnosticStage('platform-arm64');
  const wrongPlatform = buildPluginPackage(arm64Binary, key, { version: '0.9.1', architecture: 'arm64' });
  let arm64Response = await api(request, token, '/plugin-versions', { method: 'POST', headers: uploadHeaders('wrong-platform-1', wrongPlatform), body: wrongPlatform, status: 201 });
  arm64Response = await api(request, token, '/plugin-versions/' + encodeURIComponent(arm64Response.body.version_id) + '/actions/approve', {
    method: 'POST', headers: { 'Idempotency-Key': 'arm64-approve-1', 'If-Match': arm64Response.etag }, data: { approval_comment: 'valid arm64 package' }, status: 200,
  });
  arm64Response = await api(request, token, '/plugin-versions/' + encodeURIComponent(arm64Response.body.version_id) + '/actions/publish', {
    method: 'POST', headers: { 'Idempotency-Key': 'arm64-publish-1', 'If-Match': arm64Response.etag }, data: { publication_comment: 'platform mismatch fixture' }, status: 200,
  });

  await markDiagnosticStage('platform-publish');
  const archive = buildPluginPackage(binary, key, { version: '1.0.0' });
  let uploaded = await api(request, token, '/plugin-versions', { method: 'POST', headers: uploadHeaders('plugin-upload-1', archive), body: archive, status: 201 });
  let version = uploaded.body;
  version = (await api(request, token, '/plugin-versions/' + encodeURIComponent(version.version_id) + '/actions/approve', {
    method: 'POST', headers: { 'Idempotency-Key': 'plugin-approve-1', 'If-Match': uploaded.etag }, data: { approval_comment: 'acceptance approval' }, status: 200,
  })).body;
  const approvedETag = version.etag;
  version = (await api(request, token, '/plugin-versions/' + encodeURIComponent(version.version_id) + '/actions/publish', {
    method: 'POST', headers: { 'Idempotency-Key': 'plugin-publish-1', 'If-Match': approvedETag }, data: { publication_comment: 'acceptance publication' }, status: 200,
  })).body;

  await poll(async () => {
    const host = (await api(request, token, '/hosts/' + encodeURIComponent(env.HOST_ID))).body;
    return host.status === 'online' ? host : undefined;
  }, 60_000, 'enrolled Host online');
  await markDiagnosticStage('platform-discovery');
  const candidates = await poll(async () => {
    const page = (await api(request, token, '/discovery-candidates')).body;
    const docker = page.items.filter((item) => item.discovery_source === 'docker' && item.database_family === 'mysql');
    const native = page.items.filter((item) => item.discovery_source === 'native' && item.database_family === 'mysql');
    return docker.length === 2 && native.length === 1 ? { docker, native } : undefined;
  }, 120_000, 'one native fixture and two Docker MySQL candidates');
  expect(candidates.native[0].process_identity.endsWith('/mysqld-dbp')).toBe(true);
  const dockerCandidates = candidates.docker.sort((left, right) => left.candidate_id.localeCompare(right.candidate_id));
  expect(dockerCandidates.every((item) => item.normalized_endpoint && !item.normalized_endpoint.startsWith('127.0.0.1:'))).toBe(true);

  const acceptCandidate = async (candidate, index) => (await api(request, token, '/discovery-candidates/' + encodeURIComponent(candidate.candidate_id) + '/actions/accept', {
      method: 'POST',
      headers: { 'Idempotency-Key': 'accept-candidate-' + index, 'If-Match': candidate.etag },
      data: { display_name: 'Acceptance MySQL ' + (index + 1), database_family: 'mysql', database_variant: 'mysql', normalized_endpoint: candidate.normalized_endpoint, credential_ref: 'secret://acceptance/mysql', labels: { environment: 'acceptance' } },
      status: 202,
    })).body;

  await markDiagnosticStage('platform-first-accept');
  const instances = [await acceptCandidate(dockerCandidates[0], 0)];
  const firstAssignment = await poll(async () => {
    const page = (await api(request, token, '/plugin-assignments?host_id=' + encodeURIComponent(env.HOST_ID) + '&limit=10')).body;
    if (page.items.length !== 1) return undefined;
    const item = page.items[0];
    return item.observed_state?.process_state === 'running' && item.observed_state?.bound_instance_count === 1 && item.observed_state?.pid > 0 ? item : undefined;
  }, 180_000, 'first accepted MySQL starts one plugin process');
  const first_instance_pid = firstAssignment.observed_state.pid;

  await markDiagnosticStage('platform-second-accept');
  instances.push(await acceptCandidate(dockerCandidates[1], 1));

  const assignment = await poll(async () => {
    const page = (await api(request, token, '/plugin-assignments?host_id=' + encodeURIComponent(env.HOST_ID) + '&limit=10')).body;
    if (page.items.length !== 1) return undefined;
    const item = page.items[0];
    return item.observed_state?.process_state === 'running' && item.observed_state?.bound_instance_count === 2 && item.observed_state?.pid === first_instance_pid ? item : undefined;
  }, 180_000, 'the same running MySQL plugin process binds the second instance');
  expect(assignment.observed_state.pid).toBe(first_instance_pid);

  await markDiagnosticStage('platform-arm64-assignment');
  const currentAssignment = await api(request, token, '/plugin-assignments/' + encodeURIComponent(assignment.assignment_id));
  const platformProblem = await api(request, token, '/plugin-assignments/' + encodeURIComponent(assignment.assignment_id), {
    method: 'PATCH', headers: { 'Idempotency-Key': 'arm64-assignment-1', 'If-Match': currentAssignment.etag }, data: { desired_version: arm64Response.body.version }, status: 422,
  });
  expect(platformProblem.body.type).toBe('https://dbpilot.local/problems/plugin_platform_mismatch');

  await markDiagnosticStage('platform-metrics');
  await poll(async () => {
    const overview = (await api(request, token, '/monitoring/overview?from=' + encodeURIComponent(new Date(Date.now() - 10 * 60_000).toISOString()) + '&to=' + encodeURIComponent(new Date().toISOString()) + '&step=10s')).body;
    for (const instance of instances) {
      const names = new Set(overview.metrics.filter((series) => series.instance_id === instance.instance_id).map((series) => series.name));
      if (!mysqlMetrics.every((name) => names.has(name))) return undefined;
    }
    return overview;
  }, 180_000, 'five metrics for both MySQL instances');

  const state = await loadState();
  await saveState({ ...state, diagnostic_stage: 'platform-complete', version_id: version.version_id, plugin_version: version.version, assignment_id: assignment.assignment_id, assignment_pid: assignment.observed_state.pid, first_instance_pid, instance_ids: instances.map((item) => item.instance_id) });
});

test('custom template workflow rejects unsafe SQL and publishes a safe revision', async ({ request }) => {
  test.skip(phase !== 'template');
  await markDiagnosticStage('template-unsafe');
  const token = await issueToken(request, 'valid');
  const state = await loadState();

  const unsafeTemplate = (await api(request, token, '/metric-templates', {
    method: 'POST', headers: { 'Idempotency-Key': 'unsafe-template-create' },
    data: { template_id: 'mysql.acceptance.unsafe', database_family: 'mysql', name: 'Unsafe acceptance template' }, status: 201,
  })).body;
  const unsafeRevision = await api(request, token, '/metric-templates/' + encodeURIComponent(unsafeTemplate.template_id) + '/revisions', {
    method: 'POST', headers: { 'Idempotency-Key': 'unsafe-template-revision' },
    data: templateDefinition('DELETE FROM mysql.user', 'mysql.acceptance.unsafe.value'), status: 201,
  });
  const unsafeValidation = await api(request, token, '/metric-template-revisions/' + encodeURIComponent(unsafeRevision.body.revision_id) + '/actions/validate', {
    method: 'POST', headers: { 'Idempotency-Key': 'unsafe-template-validate', 'If-Match': unsafeRevision.etag }, status: 422,
  });
  expect(unsafeValidation.text).not.toContain('DELETE FROM mysql.user');

  await markDiagnosticStage('template-high-cardinality-create');
  const highCardinalityTemplate = (await api(request, token, '/metric-templates', {
    method: 'POST', headers: { 'Idempotency-Key': 'high-cardinality-template-create' },
    data: { template_id: 'mysql.acceptance.high_cardinality', database_family: 'mysql', name: 'High cardinality acceptance template' }, status: 201,
  })).body;
  let highCardinalityRevision = await api(request, token, '/metric-templates/' + encodeURIComponent(highCardinalityTemplate.template_id) + '/revisions', {
    method: 'POST', headers: { 'Idempotency-Key': 'high-cardinality-revision' }, data: highCardinalityDefinition(), status: 201,
  });
  highCardinalityRevision = await api(request, token, '/metric-template-revisions/' + encodeURIComponent(highCardinalityRevision.body.revision_id) + '/actions/validate', {
    method: 'POST', headers: { 'Idempotency-Key': 'high-cardinality-validate', 'If-Match': highCardinalityRevision.etag }, status: 200,
  });
  await markDiagnosticStage('template-high-cardinality-trial');
  const highCardinalityTrial = await api(request, token, '/metric-template-revisions/' + encodeURIComponent(highCardinalityRevision.body.revision_id) + '/actions/trial', {
    method: 'POST', headers: { 'Idempotency-Key': 'high-cardinality-trial' }, data: { instance_id: state.instance_ids[0], plugin_version_id: state.version_id }, status: 202,
  });
  await saveState({ ...await loadState(), high_cardinality_job_id: highCardinalityTrial.body.id, high_cardinality_revision_id: highCardinalityRevision.body.revision_id });
  await markDiagnosticStage('template-high-cardinality-job');
  await waitJob(request, token, highCardinalityTrial.body.id, 'failed');
  await markDiagnosticStage('template-high-cardinality-result');
  const failedHighCardinality = await poll(async () => {
    const page = (await api(request, token, '/metric-templates/' + encodeURIComponent(highCardinalityTemplate.template_id) + '/revisions?limit=10')).body;
    return page.items.find((candidate) => candidate.revision_id === highCardinalityRevision.body.revision_id && candidate.status === 'trial_failed');
  }, 120_000, 'high cardinality trial classification');
  expect(failedHighCardinality.status).toBe('trial_failed');

  await markDiagnosticStage('template-safe-create');
  const template = (await api(request, token, '/metric-templates', {
    method: 'POST', headers: { 'Idempotency-Key': 'safe-template-create' },
    data: { template_id: 'mysql.acceptance.custom', database_family: 'mysql', name: 'Acceptance custom metric' }, status: 201,
  })).body;
  let revisionResponse = await api(request, token, '/metric-templates/' + encodeURIComponent(template.template_id) + '/revisions', {
    method: 'POST', headers: { 'Idempotency-Key': 'safe-template-revision' },
    data: templateDefinition('SELECT 1 AS value', 'mysql.acceptance.custom.value'), status: 201,
  });
  let revision = revisionResponse.body;
  revisionResponse = await api(request, token, '/metric-template-revisions/' + encodeURIComponent(revision.revision_id) + '/actions/validate', {
    method: 'POST', headers: { 'Idempotency-Key': 'safe-template-validate', 'If-Match': revisionResponse.etag }, status: 200,
  });
  revision = revisionResponse.body;
  await markDiagnosticStage('template-safe-trial');
  const trial = await api(request, token, '/metric-template-revisions/' + encodeURIComponent(revision.revision_id) + '/actions/trial', {
    method: 'POST', headers: { 'Idempotency-Key': 'safe-template-trial' }, data: { instance_id: state.instance_ids[0], plugin_version_id: state.version_id }, status: 202,
  });
  await waitJob(request, token, trial.body.id, 'succeeded');

  revision = await poll(async () => {
    const page = (await api(request, token, '/metric-templates/' + encodeURIComponent(template.template_id) + '/revisions?limit=10')).body;
    const item = page.items.find((candidate) => candidate.revision_id === revision.revision_id);
    return item?.status === 'approval_pending' || item?.status === 'trial_passed' ? item : undefined;
  }, 120_000, 'template trial completion');

  await markDiagnosticStage('template-publish');
  const approver = await issueToken(request, 'approver');
  revisionResponse = await api(request, approver, '/metric-template-revisions/' + encodeURIComponent(revision.revision_id) + '/actions/approve', {
    method: 'POST', headers: { 'Idempotency-Key': 'safe-template-approve', 'If-Match': revision.etag }, data: { approval_comment: 'separate acceptance approver' }, status: 200,
  });
  revisionResponse = await api(request, approver, '/metric-template-revisions/' + encodeURIComponent(revision.revision_id) + '/actions/publish', {
    method: 'POST', headers: { 'Idempotency-Key': 'safe-template-publish', 'If-Match': revisionResponse.etag }, status: 200,
  });
  expect(revisionResponse.body.status).toBe('published');
  await saveState({ ...state, template_id: template.template_id, template_revision_id: revision.revision_id, high_cardinality_job_id: highCardinalityTrial.body.id, high_cardinality_revision_id: highCardinalityRevision.body.revision_id });
});

test('stop makes database metrics stale and restart recovers same assignment', async ({ request }) => {
  test.skip(!['stop', 'restart'].includes(phase));
  await markDiagnosticStage('plugin-' + phase);
  const token = await issueToken(request, 'valid');
  const state = await loadState();
  let assignmentResponse = await api(request, token, '/plugin-assignments/' + encodeURIComponent(state.assignment_id));
  const desired = phase === 'stop' ? 'stopped' : 'running';
  assignmentResponse = await api(request, token, '/plugin-assignments/' + encodeURIComponent(state.assignment_id), {
    method: 'PATCH', headers: { 'Idempotency-Key': 'assignment-' + phase, 'If-Match': assignmentResponse.etag }, data: { desired_state: desired }, status: 200,
  });
  const assignment = await poll(async () => {
    const current = (await api(request, token, '/plugin-assignments/' + encodeURIComponent(state.assignment_id))).body;
    const wanted = phase === 'stop' ? 'stopped' : 'running';
    return current.observed_state?.process_state === wanted ? current : undefined;
  }, 120_000, 'plugin ' + desired);
  expect(assignment.assignment_id).toBe(state.assignment_id);

  if (phase === 'stop') {
    await poll(async () => {
      const overview = (await api(request, token, monitoringURL())).body;
      const database = overview.metrics.filter((series) => state.instance_ids.includes(series.instance_id) && mysqlMetrics.includes(series.name));
      return database.length >= 10 && database.every((series) => series.status === 'stale' && series.buckets.at(-1)?.value === null) ? overview : undefined;
    }, 120_000, 'database metrics stale without synthetic zero');
  } else {
    await poll(async () => {
      const overview = (await api(request, token, monitoringURL())).body;
      const database = overview.metrics.filter((series) => state.instance_ids.includes(series.instance_id) && mysqlMetrics.includes(series.name));
      return database.length >= 10 && database.some((series) => series.status === 'healthy') ? overview : undefined;
    }, 120_000, 'database metrics recover');
  }
});

test('failed upgrade automatically rolls back to the previous healthy version', async ({ request }) => {
  test.skip(phase !== 'rollback');
  await markDiagnosticStage('plugin-rollback');
  const token = await issueToken(request, 'valid');
  const state = await loadState();
  const badBinary = await readFile('/acceptance/bin/dbpilot-docker-discovery');
  const key = await readFile(env.PLUGIN_PUBLISHER_KEY_FILE);
  const archive = buildPluginPackage(badBinary, key, { version: '1.1.0' });
  let response = await api(request, token, '/plugin-versions', { method: 'POST', headers: uploadHeaders('bad-upgrade-upload', archive), body: archive, status: 201 });
  let badVersion = response.body;
  response = await api(request, token, '/plugin-versions/' + encodeURIComponent(badVersion.version_id) + '/actions/approve', {
    method: 'POST', headers: { 'Idempotency-Key': 'bad-upgrade-approve', 'If-Match': response.etag }, data: {}, status: 200,
  });
  response = await api(request, token, '/plugin-versions/' + encodeURIComponent(badVersion.version_id) + '/actions/publish', {
    method: 'POST', headers: { 'Idempotency-Key': 'bad-upgrade-publish', 'If-Match': response.etag }, data: {}, status: 200,
  });
  badVersion = response.body;
  let assignmentResponse = await api(request, token, '/plugin-assignments/' + encodeURIComponent(state.assignment_id));
  await api(request, token, '/plugin-assignments/' + encodeURIComponent(state.assignment_id), {
    method: 'PATCH', headers: { 'Idempotency-Key': 'bad-upgrade-assign', 'If-Match': assignmentResponse.etag }, data: { desired_version: badVersion.version }, status: 200,
  });
  const rolledBack = await poll(async () => {
    const current = (await api(request, token, '/plugin-assignments/' + encodeURIComponent(state.assignment_id))).body;
    return current.observed_state?.installed_version === state.plugin_version
      && current.observed_state?.process_state === 'running'
      && current.observed_state?.last_error_code === 'plugin_upgrade_rolled_back' ? current : undefined;
  }, 180_000, 'failed upgrade rollback');
  expect(rolledBack.observed_state.bound_instance_count).toBe(2);
  assignmentResponse = await api(request, token, '/plugin-assignments/' + encodeURIComponent(state.assignment_id));
  await api(request, token, '/plugin-assignments/' + encodeURIComponent(state.assignment_id), {
    method: 'PATCH', headers: { 'Idempotency-Key': 'restore-good-version', 'If-Match': assignmentResponse.etag }, data: { desired_version: state.plugin_version }, status: 200,
  });
  await poll(async () => {
    const current = (await api(request, token, '/plugin-assignments/' + encodeURIComponent(state.assignment_id))).body;
    return current.desired_version === state.plugin_version && current.observed_state?.installed_version === state.plugin_version && current.observed_state?.process_state === 'running' ? current : undefined;
  }, 120_000, 'restored good desired version');
});

test('Agent and Server restart require observations and all ten series after an explicit boundary', async ({ request }) => {
  test.skip(!['capture-agent-restart', 'capture-agent-stopped', 'convergence-agent', 'capture-server-restart', 'capture-server-stopped', 'convergence-server'].includes(phase));
  await markDiagnosticStage(phase);
  const token = await issueToken(request, 'valid');
  const state = await loadState();
  const restartKind = phase.includes('agent') ? 'agent' : 'server';
  if (phase.endsWith('-stopped')) {
    const boundary = state.restart_boundaries?.[restartKind];
    expect(boundary?.observed_at).toBeTruthy();
    expect(restartBoundaryUTC).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(Date.parse(restartBoundaryUTC)).toBeGreaterThanOrEqual(Date.parse(boundary.sample_at));
    await saveState({ ...state, restart_boundaries: { ...state.restart_boundaries, [restartKind]: { ...boundary, sample_at: restartBoundaryUTC } } });
    return;
  }
  if (phase.startsWith('capture-')) {
    const assignment = (await api(request, token, '/plugin-assignments/' + encodeURIComponent(state.assignment_id))).body;
    expect(assignment.observed_state?.process_state).toBe('running');
    const overview = (await api(request, token, monitoringURL())).body;
    const current = currentMySQLSeries(overview, state.instance_ids);
    expect(current).toHaveLength(10);
    const sampleAt = latestNonNullSampleAt(current);
    expect(sampleAt).toBeTruthy();
    await saveState({ ...state, restart_boundaries: { ...(state.restart_boundaries ?? {}), [restartKind]: { observed_at: assignment.observed_state.observed_at, sample_at: sampleAt } } });
    return;
  }
  const boundary = state.restart_boundaries?.[restartKind];
  expect(boundary?.observed_at).toBeTruthy();
  expect(boundary?.sample_at).toBeTruthy();
  const assignment = await poll(async () => {
    const current = (await api(request, token, '/plugin-assignments/' + encodeURIComponent(state.assignment_id))).body;
    return current.desired_state === 'running' && current.observed_state?.process_state === 'running' && current.observed_state?.bound_instance_count === 2
      && Date.parse(current.observed_state.observed_at) > Date.parse(boundary.observed_at) ? current : undefined;
  }, 180_000, restartKind + ' post-restart observation convergence');
  expect(assignment.configuration_revision).toBeGreaterThan(0);
  await poll(async () => {
    const overview = (await api(request, token, monitoringURL())).body;
    const database = currentMySQLSeries(overview, state.instance_ids);
    return database.length === 10 && database.every((series) => series.status === 'healthy' && series.buckets.some((bucket) => bucket.value !== null && Date.parse(bucket.at) > Date.parse(boundary.sample_at))) ? overview : undefined;
  }, 120_000, restartKind + ' post-restart ten-series convergence');
  // The final PostgreSQL assertion checks the stronger persisted identity
  // tuple (Agent, metric, series_fingerprint, sampled_at) for zero duplicates.
});

test('React monitoring route renders real scoped metrics without token exposure', async ({ page, request }) => {
  test.skip(phase !== 'browser');
  await markDiagnosticStage('browser');
  const token = await issueToken(request, 'valid');
  let currentToken = token;
  await page.exposeFunction('__DBPilotAcceptanceReadToken', async () => currentToken);
  await page.addInitScript(() => {
    Object.defineProperty(globalThis, '__DBPilotAcceptanceTokenProvider', { configurable: false, enumerable: false, writable: false, value: async () => globalThis.__DBPilotAcceptanceReadToken() });
  });
  const authorizationHeaders = [];
  page.on('request', (outbound) => {
    if (outbound.url().includes('/monitoring/overview')) authorizationHeaders.push(outbound.headers().authorization ?? '');
  });
  await page.goto(env.FRONTEND_URL + '/monitoring');
  await expect(page.getByRole('heading', { name: '基础监控' })).toBeVisible();
  for (const name of mysqlMetrics) await expect(page.getByText(name).first()).toBeVisible();
  await expect.poll(() => authorizationHeaders).toContain('Bearer ' + token);
  await new Promise((resolve) => setTimeout(resolve, 1100));
  const rotatedToken = await issueToken(request, 'valid');
  expect(rotatedToken).not.toBe(token);
  currentToken = rotatedToken;
  await page.reload();
  await expect(page.getByRole('heading', { name: '基础监控' })).toBeVisible();
  await expect.poll(() => authorizationHeaders).toContain('Bearer ' + rotatedToken);
  const html = await page.content();
  expect(html).not.toContain(token);
  expect(html).not.toContain(rotatedToken);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
});

test('real Task17 failure path retains no prohibited canary class', async ({ page, request }) => {
  test.skip(phase !== 'failure-canary');
  await markDiagnosticStage('failure-canary');
  const token = await issueToken(request, 'valid');
  const invalidPackage = Buffer.from(failureCanaries.packageBytes + '\n' + failureCanaries.nonPemKey, 'utf8');
  const packageProblem = await api(request, token, '/plugin-versions', {
    method: 'POST', headers: uploadHeaders('failure-canary-package', invalidPackage), body: invalidPackage, status: 422,
  });
  for (const canary of Object.values(failureCanaries)) expect(packageProblem.text).not.toContain(canary);

  const template = (await api(request, token, '/metric-templates', {
    method: 'POST', headers: { 'Idempotency-Key': 'failure-canary-template' },
    data: { template_id: 'mysql.acceptance.failure_canary', database_family: 'mysql', name: 'Failure canary template' }, status: 201,
  })).body;
  const revision = await api(request, token, '/metric-templates/' + encodeURIComponent(template.template_id) + '/revisions', {
    method: 'POST', headers: { 'Idempotency-Key': 'failure-canary-revision' },
    data: templateDefinition('DELETE FROM mysql.user /* ' + failureCanaries.sql + ' */', 'mysql.acceptance.failure_canary.value'), status: 201,
  });
  const validationProblem = await api(request, token, '/metric-template-revisions/' + encodeURIComponent(revision.body.revision_id) + '/actions/validate', {
    method: 'POST', headers: { 'Idempotency-Key': 'failure-canary-validate', 'If-Match': revision.etag }, status: 422,
  });
  for (const canary of Object.values(failureCanaries)) expect(validationProblem.text).not.toContain(canary);

  const candidates = await api(request, token, '/discovery-candidates');
  const monitoring = await api(request, token, monitoringURL());
  for (const canary of Object.values(failureCanaries)) {
    expect(candidates.text).not.toContain(canary);
    expect(monitoring.text).not.toContain(canary);
  }
  await page.addInitScript((value) => {
    Object.defineProperty(globalThis, '__DBPilotAcceptanceTokenProvider', { configurable: false, enumerable: false, writable: false, value: async () => value });
  }, token);
  await page.goto(env.FRONTEND_URL + '/monitoring');
  const dom = await page.content();
  for (const canary of Object.values(failureCanaries)) expect(dom).not.toContain(canary);
  throw new Error('intentional Task17 failure-canary phase');
});

function currentMySQLSeries(overview, instanceIDs) {
  return overview.metrics.filter((series) => instanceIDs.includes(series.instance_id) && mysqlMetrics.includes(series.name));
}

function latestNonNullSampleAt(series) {
  const timestamps = series.flatMap((item) => item.buckets.filter((bucket) => bucket.value !== null).map((bucket) => Date.parse(bucket.at))).filter(Number.isFinite);
  return timestamps.length > 0 ? new Date(Math.max(...timestamps)).toISOString() : '';
}

function templateDefinition(statement, metricName) {
  return {
    variants: ['mysql'], name: metricName, query_kind: 'sql', read_only_statement: statement,
    collection_interval_seconds: 10, timeout_seconds: 5, max_rows: 10, max_columns: 4,
    value_mappings: [{ source_column: 'value', metric_name: metricName, metric_type: 'gauge', unit: '1' }],
    label_mappings: [], cardinality_limit: 10,
  };
}

function highCardinalityDefinition() {
  return {
    variants: ['mysql'], name: 'High cardinality acceptance metric', query_kind: 'sql',
    read_only_statement: "WITH RECURSIVE seq AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM seq WHERE n < 11) SELECT n AS value, CONCAT('" + failureCanaries.trialRow + "-', n) AS dimension FROM seq",
    collection_interval_seconds: 10, timeout_seconds: 5, max_rows: 20, max_columns: 4,
    value_mappings: [{ source_column: 'value', metric_name: 'mysql.acceptance.high_cardinality.value', metric_type: 'gauge', unit: '1' }],
    label_mappings: [{ source_column: 'dimension', label: 'dimension' }], cardinality_limit: 5,
  };
}

function monitoringURL() {
  return '/monitoring/overview?from=' + encodeURIComponent(new Date(Date.now() - 10 * 60_000).toISOString()) + '&to=' + encodeURIComponent(new Date().toISOString()) + '&step=10s';
}

async function issueToken(request, variant) {
  const credential = (await readFile(env.OIDC_CREDENTIAL_FILE, 'utf8')).trim();
  const response = await request.post(env.OIDC_URL + '/token', { ignoreHTTPSErrors: true, data: { credential, variant } });
  expect(response.status()).toBe(200);
  const body = await response.json();
  expect(body.access_token).toBeTruthy();
  return body.access_token;
}

async function api(request, token, path, options = {}) {
  const headers = { Accept: 'application/json', Authorization: 'Bearer ' + token, ...(options.headers ?? {}) };
  const response = await request.fetch(env.FRONTEND_URL + scopePath + path, {
    ignoreHTTPSErrors: true, method: options.method ?? 'GET', headers,
    data: options.body ?? options.data,
  });
  const text = await response.text();
  const expected = options.status ?? 200;
  expect(response.status(), text).toBe(expected);
  let body = {};
  if (text) {
    try { body = JSON.parse(text); } catch { body = {}; }
  }
  return { body, text, etag: response.headers().etag ?? body.etag };
}

async function waitJob(request, token, jobID, outcome) {
  let lastDiagnosticStatus = '';
  return poll(async () => {
    const job = (await api(request, token, '/jobs/' + encodeURIComponent(jobID))).body;
    if (outcome === 'failed' && job.status !== lastDiagnosticStatus && /^[a-z_]+$/.test(job.status)) {
      lastDiagnosticStatus = job.status;
      await markDiagnosticStage('job-status-' + job.status.replaceAll('_', '-'));
    }
    if (job.status === 'failed' || job.status === 'cancelled' || job.status === 'timed_out') {
      if (outcome !== 'failed') throw new Error('job failed: ' + job.outcome);
      return job;
    }
    if (job.status === 'succeeded' && outcome === 'failed') {
      await markDiagnosticStage('job-unexpected-success');
      throw new Error('job unexpectedly succeeded');
    }
    return job.status === 'succeeded' && outcome === 'succeeded' ? job : undefined;
  }, 120_000, 'job ' + jobID);
}

async function poll(operation, timeout, label) {
  const deadline = Date.now() + timeout;
  let last;
  while (Date.now() < deadline) {
    try {
      const value = await operation();
      if (value) return value;
    } catch (error) {
      last = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error('timed out waiting for ' + label + (last ? ': ' + last.message : ''));
}

async function loadState() {
  return JSON.parse(await readFile(env.ACCEPTANCE_STATE_FILE, 'utf8'));
}

async function markDiagnosticStage(diagnostic_stage) {
  const state = await loadState();
  await saveState({ ...state, diagnostic_stage });
}

async function saveState(value) {
  const safe = JSON.stringify(value);
  for (const forbidden of ['token', 'password', 'statement', 'private', 'signed_url']) {
    if (safe.toLowerCase().includes(forbidden)) throw new Error('unsafe retained state key');
  }
  await writeFile(env.ACCEPTANCE_STATE_FILE + '.tmp', safe + '\n', { mode: 0o600 });
  await rename(env.ACCEPTANCE_STATE_FILE + '.tmp', env.ACCEPTANCE_STATE_FILE);
}

function uploadHeaders(key, archive) {
  return { 'Idempotency-Key': key, 'Content-Type': 'application/gzip', 'Content-Length': String(archive.length) };
}
