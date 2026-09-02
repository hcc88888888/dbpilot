import { test, expect } from '@playwright/test';
import { chmod, readFile, rename, writeFile } from 'node:fs/promises';
import { createHash, sign } from 'node:crypto';
import { gzipSync } from 'node:zlib';

const required = [
  'FRONTEND_URL', 'OIDC_URL', 'OIDC_CREDENTIAL_FILE', 'PLUGIN_PUBLISHER_KEY_FILE',
  'PLUGIN_BINARY_FILE', 'TENANT_ID', 'PROJECT_ID', 'HOST_ID', 'AGENT_ID',
  'AGENT_DATA_DIR', 'ACCEPTANCE_STATE_FILE', 'DBPILOT_ACCEPTANCE_PHASE',
];
const env = Object.fromEntries(required.map((name) => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(name + ' is required');
  return [name, value];
}));
const scopePath = '/api/v1/tenants/' + encodeURIComponent(env.TENANT_ID) + '/projects/' + encodeURIComponent(env.PROJECT_ID);
const phase = env.DBPILOT_ACCEPTANCE_PHASE;
const mysqlMetrics = ['mysql.connections.current', 'mysql.queries.total', 'mysql.threads.running', 'mysql.up', 'mysql.uptime.seconds'];

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
  const tokenPath = env.AGENT_DATA_DIR + '/enrollment-token';
  await writeFile(tokenPath + '.tmp', response.body.enrollment_token + '\n', { mode: 0o600 });
  await rename(tokenPath + '.tmp', tokenPath);
  await chmod(tokenPath, 0o600);
  await saveState({ enrollment_revision: response.body.enrollment_revision });
});

test('publish signed plugin, discover two internal-only MySQLs, and converge one process', async ({ request }) => {
  test.skip(phase !== 'platform');
  const token = await issueToken(request, 'valid');
  const binary = await readFile(env.PLUGIN_BINARY_FILE);
  const key = await readFile(env.PLUGIN_PUBLISHER_KEY_FILE);
  const tampered = buildPackage(binary, key, { version: '0.9.0' });
  tampered[tampered.length - 40] ^= 0xff;
  await api(request, token, '/plugin-versions', { method: 'POST', headers: uploadHeaders('tampered-1', tampered), body: tampered, status: 422 });
  const wrongPlatform = buildPackage(binary, key, { version: '0.9.1', architecture: 'arm64' });
  await api(request, token, '/plugin-versions', { method: 'POST', headers: uploadHeaders('wrong-platform-1', wrongPlatform), body: wrongPlatform, status: 422 });

  const archive = buildPackage(binary, key, { version: '1.0.0' });
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
  const candidates = await poll(async () => {
    const page = (await api(request, token, '/discovery-candidates')).body;
    const docker = page.items.filter((item) => item.discovery_source === 'docker' && item.database_family === 'mysql');
    const native = page.items.filter((item) => item.discovery_source === 'native' && item.database_family === 'mysql');
    return docker.length === 2 && native.length === 1 ? { docker, native } : undefined;
  }, 120_000, 'one native fixture and two Docker MySQL candidates');
  expect(candidates.native[0].process_identity.endsWith('/mysqld-dbp')).toBe(true);
  const dockerCandidates = candidates.docker;
  expect(dockerCandidates.every((item) => item.normalized_endpoint && !item.normalized_endpoint.startsWith('127.0.0.1:'))).toBe(true);

  const instances = [];
  for (let index = 0; index < dockerCandidates.length; index += 1) {
    const candidate = dockerCandidates[index];
    const accepted = await api(request, token, '/discovery-candidates/' + encodeURIComponent(candidate.candidate_id) + '/actions/accept', {
      method: 'POST',
      headers: { 'Idempotency-Key': 'accept-candidate-' + index, 'If-Match': candidate.etag },
      data: { display_name: 'Acceptance MySQL ' + (index + 1), database_family: 'mysql', database_variant: 'mysql', normalized_endpoint: candidate.normalized_endpoint, credential_ref: 'secret://acceptance/mysql', labels: { environment: 'acceptance' } },
      status: 202,
    });
    instances.push(accepted.body);
  }

  const assignment = await poll(async () => {
    const page = (await api(request, token, '/plugin-assignments?host_id=' + encodeURIComponent(env.HOST_ID) + '&limit=10')).body;
    if (page.items.length !== 1) return undefined;
    const item = page.items[0];
    return item.observed_state?.process_state === 'running' && item.observed_state?.bound_instance_count === 2 ? item : undefined;
  }, 180_000, 'one running MySQL plugin bound to two instances');
  expect(assignment.observed_state.pid).toBeGreaterThan(0);

  await poll(async () => {
    const overview = (await api(request, token, '/monitoring/overview?from=' + encodeURIComponent(new Date(Date.now() - 10 * 60_000).toISOString()) + '&to=' + encodeURIComponent(new Date().toISOString()) + '&step=10s')).body;
    for (const instance of instances) {
      const names = new Set(overview.metrics.filter((series) => series.instance_id === instance.instance_id).map((series) => series.name));
      if (!mysqlMetrics.every((name) => names.has(name))) return undefined;
    }
    return overview;
  }, 180_000, 'five metrics for both MySQL instances');

  const state = await loadState();
  await saveState({ ...state, version_id: version.version_id, plugin_version: version.version, assignment_id: assignment.assignment_id, assignment_pid: assignment.observed_state.pid, instance_ids: instances.map((item) => item.instance_id) });
});

test('custom template workflow rejects unsafe SQL and publishes a safe revision', async ({ request }) => {
  test.skip(phase !== 'template');
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
  const trial = await api(request, token, '/metric-template-revisions/' + encodeURIComponent(revision.revision_id) + '/actions/trial', {
    method: 'POST', headers: { 'Idempotency-Key': 'safe-template-trial' }, data: { instance_id: state.instance_ids[0], plugin_version_id: state.version_id }, status: 202,
  });
  await waitJob(request, token, trial.body.id, 'succeeded');

  revision = await poll(async () => {
    const page = (await api(request, token, '/metric-templates/' + encodeURIComponent(template.template_id) + '/revisions?limit=10')).body;
    const item = page.items.find((candidate) => candidate.revision_id === revision.revision_id);
    return item?.status === 'approval_pending' || item?.status === 'trial_passed' ? item : undefined;
  }, 120_000, 'template trial completion');

  const approver = await issueToken(request, 'approver');
  revisionResponse = await api(request, approver, '/metric-template-revisions/' + encodeURIComponent(revision.revision_id) + '/actions/approve', {
    method: 'POST', headers: { 'Idempotency-Key': 'safe-template-approve', 'If-Match': revision.etag }, data: { approval_comment: 'separate acceptance approver' }, status: 200,
  });
  revisionResponse = await api(request, approver, '/metric-template-revisions/' + encodeURIComponent(revision.revision_id) + '/actions/publish', {
    method: 'POST', headers: { 'Idempotency-Key': 'safe-template-publish', 'If-Match': revisionResponse.etag }, status: 200,
  });
  expect(revisionResponse.body.status).toBe('published');
  await saveState({ ...state, template_id: template.template_id, template_revision_id: revision.revision_id });
});

test('stop makes database metrics stale and restart recovers same assignment', async ({ request }) => {
  test.skip(!['stop', 'restart'].includes(phase));
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
  const token = await issueToken(request, 'valid');
  const state = await loadState();
  const badBinary = await readFile('/acceptance/bin/dbpilot-docker-discovery');
  const key = await readFile(env.PLUGIN_PUBLISHER_KEY_FILE);
  const archive = buildPackage(badBinary, key, { version: '1.1.0' });
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

test('Agent and Server restart converge without duplicate logical samples', async ({ request }) => {
  test.skip(phase !== 'convergence');
  const token = await issueToken(request, 'valid');
  const state = await loadState();
  const assignment = await poll(async () => {
    const current = (await api(request, token, '/plugin-assignments/' + encodeURIComponent(state.assignment_id))).body;
    return current.desired_state === 'running' && current.observed_state?.process_state === 'running' && current.observed_state?.bound_instance_count === 2 ? current : undefined;
  }, 180_000, 'post-restart convergence');
  expect(assignment.configuration_revision).toBeGreaterThan(0);
  await poll(async () => {
    const overview = (await api(request, token, monitoringURL())).body;
    const database = overview.metrics.filter((series) => state.instance_ids.includes(series.instance_id) && mysqlMetrics.includes(series.name));
    return database.length >= 10 && database.some((series) => series.status === 'healthy' && series.buckets.some((bucket) => bucket.value !== null)) ? overview : undefined;
  }, 120_000, 'post-restart monitoring convergence');
  // The final PostgreSQL assertion checks the stronger persisted identity
  // tuple (Agent, metric, series_fingerprint, sampled_at) for zero duplicates.
});

test('React monitoring route renders real scoped metrics without token exposure', async ({ page, request }) => {
  test.skip(phase !== 'browser');
  const token = await issueToken(request, 'valid');
  await page.addInitScript((value) => {
    Object.defineProperty(globalThis, '__DBPilotAcceptanceTokenProvider', { configurable: false, enumerable: false, writable: false, value: async () => value });
  }, token);
  await page.route('**/api/v1/**', async (route) => {
    const headers = { ...route.request().headers(), authorization: 'Bearer ' + token };
    await route.continue({ headers });
  });
  await page.goto(env.FRONTEND_URL + '/monitoring');
  await expect(page.getByRole('heading', { name: '基础监控' })).toBeVisible();
  for (const name of mysqlMetrics) await expect(page.getByText(name).first()).toBeVisible();
  const html = await page.content();
  expect(html).not.toContain(token);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
});

function templateDefinition(statement, metricName) {
  return {
    variants: ['mysql'], name: metricName, query_kind: 'sql', read_only_statement: statement,
    collection_interval_seconds: 10, timeout_seconds: 5, max_rows: 10, max_columns: 4,
    value_mappings: [{ source_column: 'value', metric_name: metricName, metric_type: 'gauge', unit: '1' }],
    label_mappings: [], cardinality_limit: 10,
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
  return poll(async () => {
    const job = (await api(request, token, '/jobs/' + encodeURIComponent(jobID))).body;
    if (job.status === 'failed' || job.status === 'cancelled' || job.status === 'timed_out') {
      if (outcome !== 'failed') throw new Error('job failed: ' + job.outcome);
      return job;
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

function buildPackage(binary, privateKey, { version, architecture = 'amd64' }) {
  const binaryPath = 'plugin-package/bin/linux-amd64/dbpilot-plugin-mysql';
  const binaryDigest = sha256(binary);
  const manifest = canonicalJSON({
    binaries: [{ architecture, operating_system: 'linux', path: binaryPath, sha256: binaryDigest, size_bytes: binary.length }],
    capabilities: ['metrics.collect'],
    database_family: 'mysql',
    database_version_range: '>=8.0.0 <9.0.0',
    files: [{ path: binaryPath, sha256: binaryDigest, size_bytes: binary.length }],
    maximum_agent_protocol_version: 'v1',
    metric_template_schema_version: 1,
    minimum_agent_protocol_version: 'v1',
    plugin_id: 'mysql',
    protocol_version: 'v1',
    publisher_id: 'acceptance-publisher',
    signing_key_id: 'acceptance-key',
    supported_variants: ['mysql'],
    version,
  });
  const entries = [
    { name: 'plugin-package/manifest.json', body: Buffer.from(manifest), mode: 0o400 },
    { name: binaryPath, body: binary, mode: 0o500 },
  ];
  const content = createHash('sha256');
  content.update('dbpilot-plugin-content-v1\n');
  for (const entry of [...entries].sort((left, right) => left.name.localeCompare(right.name))) {
    lengthPrefix(content, entry.name);
    lengthPrefix(content, String(entry.body.length));
    lengthPrefix(content, sha256(entry.body));
  }
  const message = Buffer.from('dbpilot-plugin-signature-v1\nmanifest-sha256:' + sha256(Buffer.from(manifest)) + '\ncontent-sha256:' + content.digest('hex') + '\n');
  entries.push({ name: 'plugin-package/SIGNATURE.ed25519', body: sign(null, message, privateKey), mode: 0o400 });
  return gzipSync(tar(entries), { level: 9, mtime: 0 });
}

function canonicalJSON(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map((key) => goJSONString(key) + ':' + canonicalJSON(value[key])).join(',') + '}';
  return typeof value === 'string' ? goJSONString(value) : JSON.stringify(value);
}

function goJSONString(value) {
  return JSON.stringify(value).replace(/&/g, '\\u0026').replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

function lengthPrefix(hash, value) {
  hash.update(String(Buffer.byteLength(value)) + ':' + value);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function tar(entries) {
  const blocks = [];
  for (const entry of entries) {
    const header = Buffer.alloc(512);
    writeTarText(header, 0, 100, entry.name);
    writeTarOctal(header, 100, 8, entry.mode);
    writeTarOctal(header, 108, 8, 0);
    writeTarOctal(header, 116, 8, 0);
    writeTarOctal(header, 124, 12, entry.body.length);
    writeTarOctal(header, 136, 12, 0);
    header.fill(0x20, 148, 156);
    header[156] = '0'.charCodeAt(0);
    writeTarText(header, 257, 6, 'ustar');
    writeTarText(header, 263, 2, '00');
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    writeTarOctal(header, 148, 8, checksum);
    blocks.push(header, entry.body, Buffer.alloc((512 - entry.body.length % 512) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

function writeTarText(buffer, offset, length, value) {
  buffer.write(value, offset, Math.min(length, Buffer.byteLength(value)), 'utf8');
}

function writeTarOctal(buffer, offset, length, value) {
  const encoded = value.toString(8).padStart(length - 2, '0') + '\0 ';
  buffer.write(encoded, offset, length, 'ascii');
}
