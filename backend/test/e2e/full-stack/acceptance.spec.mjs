import { test, expect } from '@playwright/test';
import { readFile, rename, writeFile } from 'node:fs/promises';
import https from 'node:https';
import path from 'node:path';
import {
  assertNoSecretExposure,
  browserPhaseState,
  createFailureArtifacts,
  findingEvidenceIsComplete,
  renderedFindingMatches,
  verifyArtifactDownload,
} from './support.mjs';

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
  'ACCEPTANCE_STATE_FILE',
]);
const acceptancePhase = requireAcceptancePhase(process.env.DBPILOT_ACCEPTANCE_PHASE);
const rogueAgentIDs = Object.freeze(['agent-untrusted', 'agent-claimed-id', 'agent-certificate-id']);
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
const consoleByPage = new WeakMap();

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
  [ca, credential] = await Promise.all([
    readFile(environment.OIDC_CA_FILE),
    readFile(environment.OIDC_CREDENTIAL_FILE, 'utf8').then((value) => value.trim()),
  ]);
  if (!credential) throw new Error('OIDC credential file is empty');
  tokens = acceptancePhase === 'normal'
    ? Object.freeze({ valid: await issueToken('valid') })
    : Object.freeze({
        valid: await issueToken('valid'),
        missingPermission: await issueToken('missing_permission'),
        wrongAudience: await issueToken('wrong_audience'),
        expired: await issueToken('expired'),
      });
  if (acceptancePhase === 'unauthorized') {
    const state = JSON.parse(await readFile(environment.ACCEPTANCE_STATE_FILE, 'utf8'));
    if (typeof state?.policy_id !== 'string' || !state.policy_id.trim()) throw new Error('browser phase state is invalid');
    acceptedPolicy = { id: state.policy_id };
  }
});

test.beforeEach(async ({ page }) => {
  const entries = [];
  consoleByPage.set(page, entries);
  page.on('console', (message) => entries.push(message.text()));
});

test.afterEach(async ({ page }, testInfo) => {
  const html = await page.content().catch(() => '<html><body>DOM unavailable</body></html>');
  const currentURL = page.url();
  const consoleEntries = consoleByPage.get(page) ?? [];
  const secrets = retainedSecrets();
  let exposure;
  try {
    assertNoSecretExposure({ secrets, body: html, url: currentURL, consoleEntries });
  } catch (error) {
    exposure = error;
  }
  if (exposure || testInfo.status !== testInfo.expectedStatus) {
    const artifacts = createFailureArtifacts({ secrets, html, consoleEntries });
    await testInfo.attach('dom.html', {
      body: Buffer.from(artifacts.dom, 'utf8'),
      contentType: 'text/html',
    });
    await testInfo.attach('console.log', {
      body: Buffer.from(artifacts.console, 'utf8'),
      contentType: 'text/plain',
    });
    const replaced = await page.setContent(artifacts.screenshotMarkup).then(() => true).catch(() => false);
    if (replaced) {
      const screenshot = await page.screenshot({ type: 'png', fullPage: true }).catch(() => undefined);
      if (screenshot) await testInfo.attach('failure.png', { body: screenshot, contentType: 'image/png' });
    }
  }
  if (exposure) throw exposure;
});

phaseTest('normal', 'real Agent readiness, label policy, partial inspection, report and downloads complete through the browser', async ({ page }) => {
  await installBootstrap(page, tokens.valid, fullPermissions);

  const readiness = await waitForAgentReadiness(tokens.valid);
  auditValueForSecrets(readiness);
  expect(readiness.targets).toHaveLength(5);
  expect(readiness.online.connectivity).toBe('online');
  expect(readiness.online.capabilities).toContain('collect_now.host.v1');
  expect(readiness.online.agent_control_heartbeat_at).toBeTruthy();
  expect(readiness.offline.connectivity).toBe('offline');
  expect(readiness.rogue.every((target) => target.connectivity === 'offline')).toBe(true);
  expect(readiness.items).toHaveLength(13);

  await page.goto(new URL('/#inspection', environment.FRONTEND_URL).href);
  await auditBrowserLeaks(page);
  await requireText(page.locator('.ins-shell-source.control-plane'), '控制面服务', 'configured source was not rendered');
  await requireCount(page.locator('.ins-shell-source.demo'), 0, 'demo source was rendered in configured mode');
  await requireText(page.locator('.ins-scope'), `${environment.TENANT_ID} / ${environment.PROJECT_ID}`, 'authenticated scope was not rendered');

  await page.getByRole('button', { name: '巡检策略' }).click();
  const targetInputs = page.locator('fieldset[aria-label="巡检目标"] input[name="target_id"]');
  const itemInputs = page.locator('fieldset[aria-label="巡检项"] input[name="item_version"]');
  await auditBrowserLeaks(page);
  await requireCount(targetInputs, 5, 'expected targets were not rendered');
  await requireCount(itemInputs, 13, 'expected inspection items were not rendered');
  expect(await targetInputs.evaluateAll((inputs) => inputs.map((input) => input.value).sort())).toEqual([
    environment.EXPECTED_OFFLINE_AGENT_ID,
    environment.EXPECTED_ONLINE_AGENT_ID,
    ...rogueAgentIDs,
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
  auditValueForSecrets(acceptedPolicy);
  expect(acceptedPolicy.target_ids ?? []).toHaveLength(0);
  expect(acceptedPolicy.labels).toEqual({ environment: 'acceptance' });
  await auditBrowserLeaks(page);
  await requireText(page.locator('#toast'), '巡检策略已创建', 'policy creation confirmation was not rendered');

  const policyRow = page.locator('.ins-policy-row', { hasText: policyName });
  await policyRow.locator('[data-inspection-policy-edit]').click();
  await auditBrowserLeaks(page);
  await requireCondition(async () => Boolean(await form.getAttribute('data-inspection-policy-etag')), 'policy ETag was not rendered');
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
  auditValueForSecrets(acceptedPolicy);
  await auditBrowserLeaks(page);
  await requireText(page.locator('#toast'), '巡检策略已更新', 'policy update confirmation was not rendered');

  const updatedPolicyRow = page.locator('.ins-policy-row', { hasText: updatedPolicyName });
  const runResponsePromise = page.waitForResponse((response) => response.request().method() === 'POST' && response.url().endsWith(`/inspection-policies/${encodeURIComponent(acceptedPolicy.id)}/run`));
  await updatedPolicyRow.locator('[data-inspection-policy-run]').click();
  const runResponse = await runResponsePromise;
  expect(runResponse.status()).toBe(202);
  acceptedRun = await runResponse.json();
  auditValueForSecrets(acceptedRun);
  await auditBrowserLeaks(page);
  await requireText(page.locator('#toast'), '巡检已开始', 'inspection start confirmation was not rendered');

  acceptedRun = await pollJSON(`${scopePath}/inspection-runs/${encodeURIComponent(acceptedRun.id)}`, tokens.valid, (value) => value?.status === 'partial');
  auditValueForSecrets(acceptedRun);
  expect(acceptedRun.target_count).toBe(2);
  expect(acceptedRun.status).toBe('partial');
  expect(acceptedRun.targets).toEqual(expect.arrayContaining([
    expect.objectContaining({ agent_id: environment.EXPECTED_ONLINE_AGENT_ID, status: 'succeeded' }),
    expect.objectContaining({ agent_id: environment.EXPECTED_OFFLINE_AGENT_ID, status: 'failed', error_code: 'agent_offline' }),
  ]));

  await page.getByRole('button', { name: '执行记录' }).click();
  await page.locator(`[data-inspection-run="${acceptedRun.id}"]`).click();
  await auditBrowserLeaks(page);
  await requireText(page.locator('.ins-run-detail'), '部分完成', 'partial Run state was not rendered');
  await requireText(page.locator('.ins-run-detail'), environment.EXPECTED_ONLINE_AGENT_ID, 'online target was not rendered');
  await requireText(page.locator('.ins-run-detail'), environment.EXPECTED_OFFLINE_AGENT_ID, 'offline target was not rendered');
  await requireCount(page.locator('.ins-finding'), 13, 'expected Findings were not rendered');
  await requireCount(page.locator('.ins-finding.missing_data, .ins-finding.unsupported'), 0, 'invalid Finding levels were rendered');

  await page.locator(`[data-inspection-report="${acceptedRun.report_id}"]`).click();
  await auditBrowserLeaks(page);
  await requireCondition(() => page.locator('.ins-report-detail').isVisible(), 'inspection report was not rendered');
  acceptedReport = await apiJSON(`${scopePath}/inspection-reports/${encodeURIComponent(acceptedRun.report_id)}`, tokens.valid);
  auditValueForSecrets(acceptedReport);
  expect(acceptedReport.run_id).toBe(acceptedRun.id);
  expect(acceptedReport.findings).toHaveLength(13);
  expect(acceptedReport.findings.every((finding) => finding.target_id === environment.EXPECTED_ONLINE_AGENT_ID)).toBe(true);
  expect(acceptedReport.findings.every((finding) => !['missing_data', 'unsupported'].includes(finding.level))).toBe(true);
  expect(acceptedReport.findings.every((finding) => findingEvidenceIsComplete(finding))).toBe(true);
  const thresholdFindings = acceptedReport.findings.filter((finding) => finding.warning_threshold !== undefined || finding.critical_threshold !== undefined);
  expect(thresholdFindings.length).toBeGreaterThan(0);
  expect(thresholdFindings.every((finding) => Number.isFinite(finding.warning_threshold) && Number.isFinite(finding.critical_threshold))).toBe(true);
  const representative = thresholdFindings[0];
  const representativeMarkup = await page.locator('.ins-finding', { hasText: representative.item_id }).first().textContent().catch(() => '');
  expect(renderedFindingMatches(representativeMarkup, representative)).toBe(true);
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
  auditValueForSecrets({ job, auditPage });
  expect(job.id).toBe(acceptedReport.references.job_id);
  expect(job.progress?.total_targets).toBe(2);
  expect(auditPage.items).toEqual(expect.arrayContaining([
    expect.objectContaining({ job_id: acceptedReport.references.job_id }),
  ]));
  for (const command of acceptedReport.references.commands) {
    expect(auditPage.items.some((event) => event.command_id === command.command_id)).toBe(true);
  }
  await auditBrowserLeaks(page);
  await requireText(page.locator('.ins-report-meta'), acceptedReport.references.job_id, 'Job reference was not rendered');
  await requireText(page.locator('.ins-report-meta'), acceptedReport.references.audit_correlation, 'Audit reference was not rendered');
  for (const command of acceptedReport.references.commands) await requireText(page.locator('.ins-report-meta'), command.command_id, 'Command reference was not rendered');
  await requireText(page.locator('.ins-target-navigation'), environment.EXPECTED_ONLINE_AGENT_ID, 'report target navigation was not rendered');

  const artifacts = await Promise.all(acceptedReport.artifacts.map((reference) => apiJSON(`${scopePath}/artifacts/${encodeURIComponent(reference.artifact_id)}`, tokens.valid)));
  auditValueForSecrets(artifacts);
  expect(artifacts).toHaveLength(2);
  expect(new Set(artifacts.map((artifact) => artifact.content_type))).toEqual(new Set(['text/html; charset=utf-8', 'application/json']));
  expect(artifacts.every((artifact) => /^sha256:[a-f0-9]{64}$/.test(artifact.checksum))).toBe(true);

  const htmlDownload = await openReportDownload(page, 'html');
  const jsonDownload = await openReportDownload(page, 'json');
  verifyArtifactDownload({ format: 'html', ...htmlDownload, metadata: artifactForFormat(artifacts, 'html'), runId: acceptedRun.id });
  verifyArtifactDownload({ format: 'json', ...jsonDownload, metadata: artifactForFormat(artifacts, 'json'), runId: acceptedRun.id });
  await auditBrowserLeaks(page);
  await writeBrowserState(browserPhaseState({
    tenantID: environment.TENANT_ID,
    projectID: environment.PROJECT_ID,
    onlineAgentID: environment.EXPECTED_ONLINE_AGENT_ID,
    offlineAgentID: environment.EXPECTED_OFFLINE_AGENT_ID,
    policy: acceptedPolicy,
    run: acceptedRun,
    report: acceptedReport,
  }));
});

phaseTest('unauthorized', 'missing execute permission produces a fixed 403 state without demo fallback', async ({ page }) => {
  await installBootstrap(page, tokens.missingPermission, fullPermissions);
  await page.goto(new URL('/#inspection', environment.FRONTEND_URL).href);
  await auditBrowserLeaks(page);
  await requireText(page.locator('.ins-shell-source.control-plane'), '控制面服务', 'configured source was not rendered');
  await page.getByRole('button', { name: '巡检策略' }).click();
  const forbiddenResponsePromise = page.waitForResponse((response) => response.request().method() === 'POST' && response.url().endsWith(`/inspection-policies/${encodeURIComponent(acceptedPolicy.id)}/run`));
  await page.locator(`[data-inspection-policy-run="${acceptedPolicy.id}"]`).click();
  expect((await forbiddenResponsePromise).status()).toBe(403);
  await auditBrowserLeaks(page);
  await requireText(page.locator('#toast'), '当前账号没有该项目的巡检查看权限', 'fixed forbidden state was not rendered');
  await requireCount(page.locator('.ins-shell-source.demo'), 0, 'demo source was rendered after 403');
});

for (const [variant, tokenName] of [['wrong audience', 'wrongAudience'], ['expired', 'expired']]) {
  phaseTest('unauthorized', `${variant} token produces fixed 401 state`, async ({ page }) => {
    await installBootstrap(page, tokens[tokenName], fullPermissions);
    const unauthorizedResponsePromise = page.waitForResponse((response) => response.request().method() === 'GET' && response.url().endsWith('/inspection-overview'));
    await page.goto(new URL('/#inspection', environment.FRONTEND_URL).href);
    expect((await unauthorizedResponsePromise).status()).toBe(401);
    await auditBrowserLeaks(page);
    await requireText(page.locator('.ins-state-page[role="alert"]'), '登录状态已失效，请重新登录', 'fixed unauthorized state was not rendered');
    await requireCount(page.locator('.ins-shell-source.demo'), 0, 'demo source was rendered after 401');
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
    const rogue = rogueAgentIDs.map((agentID) => targets.find((target) => target.agent_id === agentID));
    if (targets.length !== 5 || !online || !offline || rogue.some((target) => !target) || online.connectivity !== 'online' || !online.agent_control_heartbeat_at || offline.connectivity !== 'offline' || rogue.some((target) => target.connectivity !== 'offline') || !online.capabilities?.includes('collect_now.host.v1') || itemsPage.items?.length !== 13) return undefined;
    return { targets, online, offline, rogue, items: itemsPage.items };
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
  try {
    const responsePromise = page.context().waitForEvent('response', {
      predicate: (response) => response.request().resourceType() === 'document' && new URL(response.url()).pathname.startsWith('/api/v1/artifact-downloads/'),
      timeout: 15_000,
    });
    const popupPromise = page.waitForEvent('popup', { timeout: 15_000 });
    await page.locator(`[data-inspection-report-format="${format}"]`).click();
    const [response, popup] = await Promise.all([responsePromise, popupPromise]);
    if (response.status() !== 200) throw new Error('download failed');
    const bytes = await response.body();
    const responseContentType = response.headers()['content-type'] ?? '';
    await popup.close().catch(() => {});
    return { bytes, responseContentType };
  } catch {
    throw new Error('artifact browser download failed');
  }
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

function safeError(error) {
  return String(error?.code || error?.name || 'request failed');
}

async function auditBrowserLeaks(page) {
  assertNoSecretExposure({
    secrets: retainedSecrets(),
    body: await page.content().catch(() => '<html><body>DOM unavailable</body></html>'),
    url: page.url(),
    consoleEntries: consoleByPage.get(page) ?? [],
  });
}

function auditValueForSecrets(value) {
  assertNoSecretExposure({ secrets: retainedSecrets(), body: JSON.stringify(value) });
}

function retainedSecrets() {
  return [credential, ...Object.values(tokens ?? {})].filter(Boolean);
}

async function requireText(locator, expected, message) {
  return requireCondition(async () => String(await locator.first().textContent() ?? '').includes(expected), message);
}

async function requireCount(locator, expected, message) {
  return requireCondition(async () => await locator.count() === expected, message);
}

async function requireCondition(load, message) {
  try {
    await expect.poll(async () => {
      try {
        return await load();
      } catch {
        return false;
      }
    }, { timeout: 15_000 }).toBe(true);
  } catch {
    throw new Error(message);
  }
}

function artifactForFormat(artifacts, format) {
  const expected = format === 'html' ? 'text/html; charset=utf-8' : 'application/json';
  const matches = artifacts.filter((artifact) => String(artifact.content_type).toLowerCase() === expected);
  if (matches.length !== 1) throw new Error('artifact metadata format mapping failed');
  return matches[0];
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

function requireAcceptancePhase(value) {
  if (value === 'normal' || value === 'unauthorized') return value;
  throw new Error('browser acceptance phase is invalid');
}

function phaseTest(expectedPhase, name, body) {
  return acceptancePhase === expectedPhase ? test(name, body) : test.skip(name, body);
}

async function writeBrowserState(state) {
  if (!path.isAbsolute(environment.ACCEPTANCE_STATE_FILE)) throw new Error('browser phase state path is invalid');
  const temporary = `${environment.ACCEPTANCE_STATE_FILE}.browser.tmp`;
  await writeFile(temporary, `${JSON.stringify(state)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'w' });
  await rename(temporary, environment.ACCEPTANCE_STATE_FILE);
}
}
