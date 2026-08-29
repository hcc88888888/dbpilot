import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import https from 'node:https';

if (process.env.NODE_TEST_CONTEXT === undefined) {
const environment = requireEnvironment([
  'FRONTEND_URL',
  'OIDC_URL',
  'OIDC_CA_FILE',
  'OIDC_CREDENTIAL_FILE',
  'TENANT_ID',
  'PROJECT_ID',
  'EXPECTED_ONLINE_AGENT_ID',
  'EXPECTED_OFFLINE_AGENT_ID',
]);
const scopePath = `/api/v1/tenants/${encodeURIComponent(environment.TENANT_ID)}/projects/${encodeURIComponent(environment.PROJECT_ID)}`;
const fullPermissions = Object.freeze({
  manage: true,
  'inspection:view': true,
  'inspection:manage': true,
  'inspection:execute': true,
});

let ca;
let credential;
let tokens;
let acceptedPolicy;
let acceptedRun;
let acceptedReport;

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
  [ca, credential] = await Promise.all([
    readFile(environment.OIDC_CA_FILE),
    readFile(environment.OIDC_CREDENTIAL_FILE, 'utf8').then((value) => value.trim()),
  ]);
  if (!credential) throw new Error('OIDC credential file is empty');
  tokens = Object.freeze({
    valid: await issueToken('valid'),
    missingPermission: await issueToken('missing_permission'),
    wrongAudience: await issueToken('wrong_audience'),
    expired: await issueToken('expired'),
  });
});

test.afterEach(async ({ page }, testInfo) => {
  const body = await page.locator('body').textContent().catch(() => '');
  const currentURL = page.url();
  for (const token of Object.values(tokens ?? {})) {
    expect(body).not.toContain(token);
    expect(currentURL).not.toContain(token);
  }
  if (testInfo.status !== testInfo.expectedStatus) {
    const html = await page.content().catch(() => '<html><body>DOM unavailable</body></html>');
    await testInfo.attach('dom.html', {
      body: Buffer.from(redactSecrets(html), 'utf8'),
      contentType: 'text/html',
    });
  }
});

test('real Agent readiness, label policy, partial inspection, report and downloads complete through the browser', async ({ page }) => {
  const browserConsole = [];
  page.on('console', (message) => browserConsole.push(message.text()));
  await installBootstrap(page, tokens.valid, fullPermissions);

  const readiness = await waitForAgentReadiness(tokens.valid);
  expect(readiness.targets).toHaveLength(2);
  expect(readiness.online.connectivity).toBe('online');
  expect(readiness.online.capabilities).toContain('collect_now.host.v1');
  expect(readiness.offline.connectivity).toBe('offline');
  expect(readiness.items).toHaveLength(13);

  await page.goto(new URL('/#inspection', environment.FRONTEND_URL).href);
  await expect(page.locator('.ins-shell-source.control-plane')).toHaveText('控制面服务');
  await expect(page.locator('.ins-shell-source.demo')).toHaveCount(0);
  await expect(page.locator('.ins-scope')).toContainText(`${environment.TENANT_ID} / ${environment.PROJECT_ID}`);

  await page.getByRole('button', { name: '巡检策略' }).click();
  const targetInputs = page.locator('fieldset[aria-label="巡检目标"] input[name="target_id"]');
  const itemInputs = page.locator('fieldset[aria-label="巡检项"] input[name="item_version"]');
  await expect(targetInputs).toHaveCount(2);
  await expect(itemInputs).toHaveCount(13);
  expect(await targetInputs.evaluateAll((inputs) => inputs.map((input) => input.value).sort())).toEqual([
    environment.EXPECTED_OFFLINE_AGENT_ID,
    environment.EXPECTED_ONLINE_AGENT_ID,
  ].sort());

  const policyName = `Compose label policy ${Date.now()}`;
  const form = page.locator('[data-inspection-policy-form]');
  await form.locator('input[name="name"]').fill(policyName);
  await form.locator('textarea[name="labels"]').fill('environment=acceptance');
  for (let index = 0; index < await itemInputs.count(); index += 1) await itemInputs.nth(index).check();
  expect(await targetInputs.evaluateAll((inputs) => inputs.every((input) => !input.checked))).toBe(true);
  const createResponsePromise = page.waitForResponse((response) => response.request().method() === 'POST' && response.url().endsWith('/inspection-policies'));
  await form.locator('[data-inspection-policy-save]').click();
  const createResponse = await createResponsePromise;
  expect(createResponse.status()).toBe(201);
  acceptedPolicy = await createResponse.json();
  expect(acceptedPolicy.target_ids ?? []).toHaveLength(0);
  expect(acceptedPolicy.labels).toEqual({ environment: 'acceptance' });
  await expect(page.locator('#toast')).toHaveText('巡检策略已创建');

  const policyRow = page.locator('.ins-policy-row', { hasText: policyName });
  await policyRow.locator('[data-inspection-policy-edit]').click();
  await expect(form).toHaveAttribute('data-inspection-policy-etag', /.+/);
  const etag = await form.getAttribute('data-inspection-policy-etag');
  expect(etag).toBeTruthy();
  const updatedPolicyName = `${policyName} updated`;
  await form.locator('input[name="name"]').fill(updatedPolicyName);
  const updateResponsePromise = page.waitForResponse((response) => response.request().method() === 'PATCH' && response.url().endsWith(`/inspection-policies/${encodeURIComponent(acceptedPolicy.id)}`));
  await form.locator('[data-inspection-policy-save]').click();
  const updateResponse = await updateResponsePromise;
  expect(updateResponse.status()).toBe(200);
  expect(updateResponse.request().headers()['if-match']).toBe(etag);
  acceptedPolicy = await updateResponse.json();
  await expect(page.locator('#toast')).toHaveText('巡检策略已更新');

  const updatedPolicyRow = page.locator('.ins-policy-row', { hasText: updatedPolicyName });
  const runResponsePromise = page.waitForResponse((response) => response.request().method() === 'POST' && response.url().endsWith(`/inspection-policies/${encodeURIComponent(acceptedPolicy.id)}/run`));
  await updatedPolicyRow.locator('[data-inspection-policy-run]').click();
  const runResponse = await runResponsePromise;
  expect(runResponse.status()).toBe(202);
  acceptedRun = await runResponse.json();
  await expect(page.locator('#toast')).toHaveText('巡检已开始');

  acceptedRun = await pollJSON(`${scopePath}/inspection-runs/${encodeURIComponent(acceptedRun.id)}`, tokens.valid, (value) => value?.status === 'partial');
  expect(acceptedRun.target_count).toBe(2);
  expect(acceptedRun.status).toBe('partial');
  expect(acceptedRun.targets).toEqual(expect.arrayContaining([
    expect.objectContaining({ agent_id: environment.EXPECTED_ONLINE_AGENT_ID, status: 'succeeded' }),
    expect.objectContaining({ agent_id: environment.EXPECTED_OFFLINE_AGENT_ID, status: 'failed', error_code: 'agent_offline' }),
  ]));

  await page.getByRole('button', { name: '执行记录' }).click();
  await page.locator(`[data-inspection-run="${acceptedRun.id}"]`).click();
  await expect(page.locator('.ins-run-detail')).toContainText('部分完成');
  await expect(page.locator('.ins-run-detail')).toContainText(environment.EXPECTED_ONLINE_AGENT_ID);
  await expect(page.locator('.ins-run-detail')).toContainText(environment.EXPECTED_OFFLINE_AGENT_ID);
  await expect(page.locator('.ins-finding')).toHaveCount(13);
  await expect(page.locator('.ins-finding.missing_data, .ins-finding.unsupported')).toHaveCount(0);

  await page.locator(`[data-inspection-report="${acceptedRun.report_id}"]`).click();
  await expect(page.locator('.ins-report-detail')).toBeVisible();
  acceptedReport = await apiJSON(`${scopePath}/inspection-reports/${encodeURIComponent(acceptedRun.report_id)}`, tokens.valid);
  expect(acceptedReport.run_id).toBe(acceptedRun.id);
  expect(acceptedReport.findings).toHaveLength(13);
  expect(acceptedReport.findings.every((finding) => finding.target_id === environment.EXPECTED_ONLINE_AGENT_ID)).toBe(true);
  expect(acceptedReport.findings.every((finding) => !['missing_data', 'unsupported'].includes(finding.level))).toBe(true);
  expect(acceptedReport.findings.every((finding) => safeFindingEvidence(finding))).toBe(true);
  const thresholdFindings = acceptedReport.findings.filter((finding) => finding.warning_threshold !== undefined || finding.critical_threshold !== undefined);
  expect(thresholdFindings.length).toBeGreaterThan(0);
  expect(thresholdFindings.every((finding) => Number.isFinite(finding.warning_threshold) && Number.isFinite(finding.critical_threshold))).toBe(true);
  expect(acceptedReport.references?.job_id).toBeTruthy();
  expect(acceptedReport.references?.audit_correlation).toBeTruthy();
  expect(acceptedReport.references?.commands).toEqual(expect.arrayContaining([
    expect.objectContaining({ target_id: environment.EXPECTED_ONLINE_AGENT_ID, command_id: expect.any(String) }),
    expect.objectContaining({ target_id: environment.EXPECTED_OFFLINE_AGENT_ID, command_id: expect.any(String) }),
  ]));
  const [job, auditPage] = await Promise.all([
    apiJSON(`${scopePath}/jobs/${encodeURIComponent(acceptedReport.references.job_id)}`, tokens.valid),
    apiJSON(`${scopePath}/audit-events?limit=100`, tokens.valid),
  ]);
  expect(job.id).toBe(acceptedReport.references.job_id);
  expect(job.progress?.total_targets).toBe(2);
  expect(auditPage.items).toEqual(expect.arrayContaining([
    expect.objectContaining({ job_id: acceptedReport.references.job_id }),
  ]));
  for (const command of acceptedReport.references.commands) {
    expect(auditPage.items.some((event) => event.command_id === command.command_id)).toBe(true);
  }
  await expect(page.locator('.ins-report-meta')).toContainText(acceptedReport.references.job_id);
  await expect(page.locator('.ins-report-meta')).toContainText(acceptedReport.references.audit_correlation);
  for (const command of acceptedReport.references.commands) await expect(page.locator('.ins-report-meta')).toContainText(command.command_id);
  await expect(page.locator('.ins-target-navigation')).toContainText(environment.EXPECTED_ONLINE_AGENT_ID);

  const artifacts = await Promise.all(acceptedReport.artifacts.map((reference) => apiJSON(`${scopePath}/artifacts/${encodeURIComponent(reference.artifact_id)}`, tokens.valid)));
  expect(artifacts).toHaveLength(2);
  expect(new Set(artifacts.map((artifact) => artifact.content_type))).toEqual(new Set(['text/html; charset=utf-8', 'application/json']));
  expect(artifacts.every((artifact) => /^sha256:[a-f0-9]{64}$/.test(artifact.checksum))).toBe(true);

  const htmlDownload = await openReportDownload(page, 'html');
  const jsonDownload = await openReportDownload(page, 'json');
  expect(htmlDownload.contentType).toContain('text/html');
  expect(jsonDownload.contentType).toContain('application/json');
  expect(htmlDownload.body).toContain(acceptedRun.id);
  expect(jsonDownload.body).toContain(acceptedRun.id);

  const exposed = JSON.stringify({ body: await page.locator('body').textContent(), url: page.url(), console: browserConsole });
  for (const token of Object.values(tokens)) expect(exposed).not.toContain(token);
});

test('missing execute permission produces a fixed 403 state without demo fallback', async ({ page }) => {
  await installBootstrap(page, tokens.missingPermission, fullPermissions);
  await page.goto(new URL('/#inspection', environment.FRONTEND_URL).href);
  await expect(page.locator('.ins-shell-source.control-plane')).toHaveText('控制面服务');
  await page.getByRole('button', { name: '巡检策略' }).click();
  const policyRow = page.locator('.ins-policy-row', { hasText: acceptedPolicy.name });
  const forbiddenResponsePromise = page.waitForResponse((response) => response.request().method() === 'POST' && response.url().endsWith(`/inspection-policies/${encodeURIComponent(acceptedPolicy.id)}/run`));
  await policyRow.locator('[data-inspection-policy-run]').click();
  expect((await forbiddenResponsePromise).status()).toBe(403);
  await expect(page.locator('#toast')).toHaveText('当前账号没有该项目的巡检查看权限');
  await expect(page.locator('.ins-shell-source.demo')).toHaveCount(0);
});

for (const [variant, tokenName] of [['wrong audience', 'wrongAudience'], ['expired', 'expired']]) {
  test(`${variant} token produces fixed 401 state`, async ({ page }) => {
    await installBootstrap(page, tokens[tokenName], fullPermissions);
    const unauthorizedResponsePromise = page.waitForResponse((response) => response.request().method() === 'GET' && response.url().endsWith('/inspection-overview'));
    await page.goto(new URL('/#inspection', environment.FRONTEND_URL).href);
    expect((await unauthorizedResponsePromise).status()).toBe(401);
    await expect(page.locator('.ins-state-page[role="alert"]')).toContainText('登录状态已失效，请重新登录');
    await expect(page.locator('.ins-shell-source.demo')).toHaveCount(0);
  });
}

async function installBootstrap(page, accessToken, permissions) {
  await page.addInitScript(({ token, tenantId, projectId, grants }) => {
    window.DBPILOT_CONTROL_PLANE_URL = window.location.origin;
    window.DBPILOT_GET_ACCESS_TOKEN = async () => token;
    window.DBPILOT_ALERT_CONTEXT = {
      authenticated: true,
      tenantId,
      projectId,
      permissions: grants,
    };
  }, {
    token: accessToken,
    tenantId: environment.TENANT_ID,
    projectId: environment.PROJECT_ID,
    grants: permissions,
  });
}

async function waitForAgentReadiness(accessToken) {
  return poll(async () => {
    const [targetsPage, itemsPage] = await Promise.all([
      apiJSON(`${scopePath}/inspection-targets?limit=100`, accessToken),
      apiJSON(`${scopePath}/inspection-items?limit=100`, accessToken),
    ]);
    const targets = targetsPage.items ?? [];
    const online = targets.find((target) => target.agent_id === environment.EXPECTED_ONLINE_AGENT_ID);
    const offline = targets.find((target) => target.agent_id === environment.EXPECTED_OFFLINE_AGENT_ID);
    if (targets.length !== 2 || !online || !offline || online.connectivity !== 'online' || offline.connectivity !== 'offline' || !online.capabilities?.includes('collect_now.host.v1') || itemsPage.items?.length !== 13) return undefined;
    return { targets, online, offline, items: itemsPage.items };
  }, 'Agent online/capability and inspection catalog readiness');
}

async function pollJSON(path, accessToken, predicate) {
  return poll(async () => {
    const value = await apiJSON(path, accessToken);
    return predicate(value) ? value : undefined;
  }, 'inspection terminal state');
}

async function poll(load, label, timeout = 120_000) {
  const deadline = Date.now() + timeout;
  let lastStatus = 'not ready';
  while (Date.now() < deadline) {
    try {
      const value = await load();
      if (value !== undefined) return value;
    } catch (error) {
      lastStatus = safeError(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error(`${label} timed out: ${lastStatus}`);
}

async function issueToken(variant) {
  const response = await httpsJSON(new URL('/token', environment.OIDC_URL), {
    method: 'POST',
    body: { credential, variant },
  });
  if (response.status !== 200 || response.value?.token_type !== 'Bearer' || typeof response.value?.access_token !== 'string') {
    throw new Error(`OIDC ${variant} token request failed with status ${response.status}`);
  }
  const payload = decodeJWT(response.value.access_token);
  if (!Number.isInteger(payload.iat) || !Number.isInteger(payload.exp) || payload.exp - payload.iat > 900) throw new Error(`OIDC ${variant} token lifetime is invalid`);
  return response.value.access_token;
}

async function apiJSON(path, accessToken) {
  const response = await httpsJSON(new URL(path, environment.FRONTEND_URL), {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (response.status < 200 || response.status >= 300) throw new Error(`control-plane request failed with status ${response.status}`);
  return response.value;
}

function httpsJSON(url, { method = 'GET', headers = {}, body } = {}) {
  const encoded = body === undefined ? undefined : Buffer.from(JSON.stringify(body), 'utf8');
  return new Promise((resolve, reject) => {
    const request = https.request(url, {
      method,
      ca,
      headers: {
        Accept: 'application/json',
        ...headers,
        ...(encoded === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': String(encoded.length) }),
      },
      timeout: 10_000,
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > 2 * 1024 * 1024) response.destroy(new Error('response exceeded acceptance limit'));
        else chunks.push(chunk);
      });
      response.on('end', () => {
        try {
          resolve({ status: response.statusCode ?? 0, value: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
        } catch {
          reject(new Error(`JSON response was invalid with status ${response.statusCode ?? 0}`));
        }
      });
    });
    request.on('timeout', () => request.destroy(new Error('HTTPS request timed out')));
    request.on('error', (error) => reject(new Error(safeError(error))));
    if (encoded !== undefined) request.write(encoded);
    request.end();
  });
}

async function openReportDownload(page, format) {
  const popupPromise = page.waitForEvent('popup');
  await page.locator(`[data-inspection-report-format="${format}"]`).click();
  const popup = await popupPromise;
  await popup.waitForLoadState('domcontentloaded');
  const value = await popup.evaluate(() => ({ contentType: document.contentType, body: document.body.textContent ?? '' }));
  await popup.close();
  return value;
}

function safeFindingEvidence(finding) {
  const serialized = JSON.stringify({ evidence: finding.evidence, evidence_fields: finding.evidence_fields, summary: finding.summary, recommendation: finding.recommendation });
  return serialized.length <= 80_000 && !/(?:authorization|bearer\s+eyJ|password|private key|postgres:\/\/)/i.test(serialized);
}

function decodeJWT(accessToken) {
  const segment = accessToken.split('.')[1];
  if (!segment) throw new Error('OIDC token payload is missing');
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch {
    throw new Error('OIDC token payload is invalid');
  }
}

function redactSecrets(value) {
  let redacted = String(value ?? '');
  if (credential) redacted = redacted.replaceAll(credential, '[REDACTED]');
  for (const token of Object.values(tokens ?? {})) redacted = redacted.replaceAll(token, '[REDACTED]');
  return redacted.replace(/Bearer\s+[^\s<"']+/gi, 'Bearer [REDACTED]');
}

function safeError(error) {
  return redactSecrets(error?.code || error?.name || 'request failed');
}

function requireEnvironment(names) {
  const values = {};
  for (const name of names) {
    const value = process.env[name]?.trim();
    if (!value) throw new Error(`required environment variable is missing: ${name}`);
    values[name] = value;
  }
  return Object.freeze(values);
}
}
