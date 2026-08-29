import { spawn } from 'node:child_process';
import { readFile, rename, rm, writeFile } from 'node:fs/promises';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PHASES = new Set(['normal', 'post-restart', 'unauthorized']);
const REQUIRED_CAPABILITY = 'collect_now.host.v1';

export async function runCommunicationPhase(phase, dependencies = {}) {
  if (!PHASES.has(phase)) throw new Error('communication phase is invalid');
  const sensitiveValues = dependencies.sensitiveValues ?? [];
  try {
    if (phase === 'unauthorized') {
      await requireProcessSuccess(await requiredFunction(dependencies.runProcess, 'phase process')(phase));
      return undefined;
    }

    if (phase === 'normal') {
      await waitForObservation(dependencies, communicationReady, 'Agent communication readiness timed out');
      const process = await requireProcessSuccess(await requiredFunction(dependencies.runProcess, 'phase process')(phase));
      const browserState = validateBrowserState(process.state);
      const observation = validateObservation(await requiredFunction(dependencies.observe, 'communication observer')(browserState));
      if (!communicationReady(observation)) throw new Error('Agent communication state changed before phase state capture');
      const state = mergeObservation(browserState, observation);
      await requiredFunction(dependencies.writeState, 'phase state writer')(state);
      return state;
    }

    const previous = validatePhaseState(await requiredFunction(dependencies.readState, 'phase state reader')());
    const observation = await waitForObservation(
      dependencies,
      (candidate) => postRestartAdvanced(previous, candidate),
      'post-restart communication state did not advance',
    );
    const state = Object.freeze({
      ...mergeObservation(previous, observation),
      pre_restart_accepted_at: previous.pre_restart_accepted_at ?? previous.accepted_at,
      post_restart_accepted_at: observation.accepted_at,
    });
    await requiredFunction(dependencies.writeState, 'phase state writer')(state);
    return state;
  } catch (error) {
    throw new Error(redact(String(error?.message ?? error), sensitiveValues));
  }
}

export async function collectRuntimeObservation({
  state,
  requestJSON,
  tenantID,
  projectID,
  onlineAgentID,
  offlineAgentID,
  now = new Date(),
} = {}) {
  if (typeof requestJSON !== 'function' || ![tenantID, projectID, onlineAgentID, offlineAgentID].every(validIdentifier)) {
    throw new Error('runtime communication observation input is invalid');
  }
  const scopePath = `/api/v1/tenants/${encodeURIComponent(tenantID)}/projects/${encodeURIComponent(projectID)}`;
  const from = new Date(now.getTime() - 30 * 60 * 1_000).toISOString();
  const to = now.toISOString();
  const seriesPath = `${scopePath}/monitoring/series?instance_id=${encodeURIComponent(onlineAgentID)}&metric=${encodeURIComponent('dbpilot.inspection.host.spool.pending_batch_count')}&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&step=5s`;
  const [targets, instances, series] = await Promise.all([
    requestJSON(`${scopePath}/inspection-targets?limit=100`),
    requestJSON(`${scopePath}/monitoring/instances?limit=100`),
    requestJSON(seriesPath),
  ]);
  const buckets = Array.isArray(series?.series?.buckets) ? series.series.buckets : [];
  const normalizedPoints = buckets
    .filter((bucket) => bucket?.value !== null && bucket?.value !== undefined)
    .map((bucket) => ({ at: canonicalTimestamp(bucket?.at), value: nonnegativeInteger(bucket?.value) }));
  if (normalizedPoints.length === 0) throw new Error('authenticated telemetry acceptance observation is empty');
  const latest = normalizedPoints.at(-1);
  const instance = (instances?.items ?? []).find((item) => item?.agent_id === onlineAgentID || item?.id === onlineAgentID);
  const inventory = Array.isArray(targets?.items) ? targets.items.map((item) => ({
    agent_id: String(item?.agent_id ?? ''),
    connectivity: String(item?.connectivity ?? ''),
    capabilities: Array.isArray(item?.capabilities) ? item.capabilities.map(String) : [],
  })) : [];

  let reportCount = 0;
  let findingCount = 0;
  let auditCount = 0;
  let terminalCommandID = 'pending';
  if (state !== undefined) {
    const browserState = validateBrowserState(state);
    const [report, audits] = await Promise.all([
      requestJSON(`${scopePath}/inspection-reports/${encodeURIComponent(browserState.report_id)}`),
      requestJSON(`${scopePath}/audit-events?limit=100`),
    ]);
    reportCount = report?.id === browserState.report_id ? 1 : 0;
    findingCount = Array.isArray(report?.findings) ? report.findings.length : 0;
    const commandIDs = new Set([browserState.online_command_id, browserState.offline_command_id]);
    auditCount = Array.isArray(audits?.items) ? audits.items.filter((event) => (
      event?.job_id === browserState.job_id
      || commandIDs.has(event?.command_id)
      || event?.resource_id === browserState.report_id
      || event?.resource_id === browserState.run_id
    )).length : 0;
    terminalCommandID = (report?.references?.commands ?? []).some((command) => command?.command_id === browserState.online_command_id)
      ? browserState.online_command_id
      : 'missing';
  }
  return validateObservation({
    inventory,
    accepted_at: canonicalTimestamp(instance?.last_sample_at),
    heartbeat_at: canonicalTimestamp(instance?.last_heartbeat_at),
    accepted_count: normalizedPoints.length,
    spool_observed_count: normalizedPoints.reduce((sum, point) => sum + point.value, 0),
    spool_pending_count: latest.value,
    report_count: reportCount,
    finding_count: findingCount,
    audit_count: auditCount,
    terminal_command_id: terminalCommandID,
  });
}

export function assertRogueAgentRejected(result) {
  if (!result || !['untrusted', 'mismatch'].includes(result.kind)) throw new Error('rogue Agent result is invalid');
  if (!Number.isInteger(result.inventoryRows) || !Number.isInteger(result.dataRows) || result.inventoryRows < 0 || result.dataRows < 0) {
    throw new Error('rogue Agent row counts are invalid');
  }
  if (result.inventoryRows !== 0 || result.dataRows !== 0) throw new Error('rogue Agent created inventory or data rows');
  if (!result.timedOut && result.exitCode === 0) throw new Error('rogue Agent unexpectedly completed successfully');
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  const expected = result.kind === 'untrusted'
    ? /(?:tls|x509|certificate|unknown authority|authentication handshake)/i
    : /(?:permissiondenied|permission denied|identity mismatch)/i;
  if (!expected.test(output)) throw new Error(`rogue ${result.kind} Agent rejection evidence is missing`);
}

async function waitForObservation(dependencies, predicate, timeoutMessage) {
  const observe = requiredFunction(dependencies.observe, 'communication observer');
  const wait = dependencies.wait ?? defaultWait;
  const maxAttempts = positiveInteger(dependencies.maxAttempts, 60);
  let lastError = '';
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      const observation = validateObservation(await observe());
      if (predicate(observation)) return observation;
    } catch (error) {
      lastError = String(error?.message ?? error);
    }
    if (attempt + 1 < maxAttempts) await wait();
  }
  throw new Error(lastError ? `${timeoutMessage}: ${lastError}` : timeoutMessage);
}

function communicationReady(observation) {
  const online = observation.inventory.find((agent) => agent.agent_id === 'agent-online');
  const offline = observation.inventory.find((agent) => agent.agent_id === 'agent-offline');
  return observation.inventory.length === 2
    && online?.connectivity === 'online'
    && online.capabilities.includes(REQUIRED_CAPABILITY)
    && offline?.connectivity === 'offline';
}

function postRestartAdvanced(previous, observation) {
  return communicationReady(observation)
    && Date.parse(observation.accepted_at) > Date.parse(previous.accepted_at)
    && Date.parse(observation.heartbeat_at) > Date.parse(previous.heartbeat_at)
    && observation.accepted_count > previous.accepted_count
    && observation.spool_observed_count > previous.spool_observed_count
    && observation.spool_pending_count === 0
    && observation.report_count === previous.report_count
    && observation.finding_count === previous.finding_count
    && observation.audit_count === previous.audit_count
    && observation.terminal_command_id === previous.journal_command_id;
}

function mergeObservation(state, observation) {
  return Object.freeze({
    ...state,
    accepted_at: observation.accepted_at,
    heartbeat_at: observation.heartbeat_at,
    accepted_count: observation.accepted_count,
    spool_observed_count: observation.spool_observed_count,
    spool_pending_count: observation.spool_pending_count,
    report_count: observation.report_count,
    finding_count: observation.finding_count,
    audit_count: observation.audit_count,
  });
}

function validateBrowserState(value) {
  const required = [
    'tenant_id', 'project_id', 'online_agent_id', 'offline_agent_id', 'policy_id', 'run_id', 'job_id', 'report_id',
    'online_command_id', 'offline_command_id', 'journal_command_id', 'audit_correlation',
  ];
  if (!value || value.version !== 1 || required.some((name) => !validIdentifier(value[name]))) {
    throw new Error('browser phase state is invalid');
  }
  if (value.online_agent_id === value.offline_agent_id || value.journal_command_id !== value.online_command_id || value.online_command_id === value.offline_command_id) {
    throw new Error('browser phase command identities are invalid');
  }
  return Object.freeze(Object.fromEntries(['version', ...required].map((name) => [name, value[name]])));
}

function validatePhaseState(value) {
  const state = validateBrowserState(value);
  for (const name of ['accepted_at', 'heartbeat_at']) {
    if (!validTimestamp(value[name])) throw new Error('communication phase timestamp is invalid');
  }
  for (const name of ['accepted_count', 'spool_observed_count', 'spool_pending_count', 'report_count', 'finding_count', 'audit_count']) {
    if (!Number.isSafeInteger(value[name]) || value[name] < 0) throw new Error('communication phase counter is invalid');
  }
  return Object.freeze({ ...state, ...Object.fromEntries([
    'accepted_at', 'heartbeat_at', 'accepted_count', 'spool_observed_count', 'spool_pending_count',
    'report_count', 'finding_count', 'audit_count',
  ].map((name) => [name, value[name]])) });
}

function validateObservation(value) {
  if (!value || !Array.isArray(value.inventory)) throw new Error('communication observation is invalid');
  const inventory = value.inventory.map((agent) => {
    if (!agent || !validIdentifier(agent.agent_id) || !['online', 'offline'].includes(agent.connectivity) || !Array.isArray(agent.capabilities)) {
      throw new Error('Agent communication observation is invalid');
    }
    return { agent_id: agent.agent_id, connectivity: agent.connectivity, capabilities: agent.capabilities.map(String) };
  });
  if (!validTimestamp(value.accepted_at) || !validTimestamp(value.heartbeat_at)) throw new Error('communication observation timestamp is invalid');
  for (const name of ['accepted_count', 'spool_observed_count', 'spool_pending_count', 'report_count', 'finding_count', 'audit_count']) {
    if (!Number.isSafeInteger(value[name]) || value[name] < 0) throw new Error('communication observation counter is invalid');
  }
  if (!validIdentifier(value.terminal_command_id)) throw new Error('terminal command observation is invalid');
  return Object.freeze({ ...value, inventory });
}

async function requireProcessSuccess(result) {
  if (!result || result.exitCode !== 0) throw new Error('acceptance phase process failed');
  return result;
}

function requiredFunction(value, name) {
  if (typeof value !== 'function') throw new Error(`${name} is required`);
  return value;
}

function validIdentifier(value) {
  return typeof value === 'string' && value.length > 0 && value === value.trim() && !/[\r\n\t]/.test(value);
}

function validTimestamp(value) {
  return typeof value === 'string' && value === value.trim() && Number.isFinite(Date.parse(value));
}

function positiveInteger(value, fallback) {
  return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

function nonnegativeInteger(value) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) throw new Error('spool counter observation is invalid');
  return number;
}

function canonicalTimestamp(value) {
  if (!validTimestamp(value)) throw new Error('runtime communication timestamp is invalid');
  return value;
}

function redact(message, sensitiveValues) {
  let result = message.replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]');
  for (const sensitive of [...new Set(sensitiveValues.map(String).filter(Boolean))].sort((a, b) => b.length - a.length)) {
    result = result.replaceAll(sensitive, '[REDACTED]');
  }
  return result;
}

function defaultWait() {
  return new Promise((resolve) => setTimeout(resolve, 1_000));
}

async function commandMain(arguments_) {
  if (arguments_.length !== 1 || !PHASES.has(arguments_[0])) {
    process.stderr.write('communication phase is invalid\n');
    return 2;
  }
  const phase = arguments_[0];
  let sensitiveValues = [];
  try {
    const runtime = await createRuntimeDependencies();
    sensitiveValues = runtime.sensitiveValues;
    await runCommunicationPhase(phase, runtime);
    process.stdout.write(`communication phase ${phase} passed\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`${redact(String(error?.message ?? error), sensitiveValues)}\n`);
    return 1;
  }
}

async function createRuntimeDependencies() {
  const environment = requiredEnvironment([
    'FRONTEND_URL', 'OIDC_URL', 'OIDC_CA_FILE', 'OIDC_CREDENTIAL_FILE', 'ACCEPTANCE_STATE_FILE',
    'TENANT_ID', 'PROJECT_ID', 'EXPECTED_ONLINE_AGENT_ID', 'EXPECTED_OFFLINE_AGENT_ID',
  ]);
  if (!path.isAbsolute(environment.OIDC_CA_FILE) || !path.isAbsolute(environment.OIDC_CREDENTIAL_FILE) || !path.isAbsolute(environment.ACCEPTANCE_STATE_FILE)) {
    throw new Error('communication file path is invalid');
  }
  const [ca, rawCredential] = await Promise.all([
    readFile(environment.OIDC_CA_FILE),
    readFile(environment.OIDC_CREDENTIAL_FILE, 'utf8'),
  ]);
  const credential = rawCredential.trim();
  if (!credential) throw new Error('OIDC credential is unavailable');
  const tokenResponse = await httpsJSON(new URL('/token', environment.OIDC_URL), ca, {
    method: 'POST', body: { credential, variant: 'valid' },
  });
  const accessToken = tokenResponse.status === 200 ? tokenResponse.value?.access_token : undefined;
  if (typeof accessToken !== 'string' || !accessToken) throw new Error('OIDC valid token request failed');
  const requestJSON = async (requestPath) => {
    const response = await httpsJSON(new URL(requestPath, environment.FRONTEND_URL), ca, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (response.status < 200 || response.status >= 300) throw new Error(`authenticated communication request failed with status ${response.status}`);
    return response.value;
  };
  const readState = async () => JSON.parse(await readFile(environment.ACCEPTANCE_STATE_FILE, 'utf8'));
  const writeState = async (state) => {
    const temporary = `${environment.ACCEPTANCE_STATE_FILE}.tmp`;
    await writeFile(temporary, `${JSON.stringify(state)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'w' });
    await rename(temporary, environment.ACCEPTANCE_STATE_FILE);
  };
  return {
    sensitiveValues: [credential, accessToken],
    maxAttempts: 120,
    observe: async (state) => collectRuntimeObservation({
      state, requestJSON,
      tenantID: environment.TENANT_ID, projectID: environment.PROJECT_ID,
      onlineAgentID: environment.EXPECTED_ONLINE_AGENT_ID, offlineAgentID: environment.EXPECTED_OFFLINE_AGENT_ID,
    }),
    readState,
    writeState,
    runProcess: async (phase) => {
      if (phase === 'normal') await rm(environment.ACCEPTANCE_STATE_FILE, { force: true });
      const result = await spawnPhaseProcess(phase, environment);
      if (phase === 'normal' && result.exitCode === 0) result.state = await readState();
      return result;
    },
  };
}

function spawnPhaseProcess(phase, environment) {
  return new Promise((resolve, reject) => {
    const child = spawn('npx', ['playwright', 'test', '--config', 'playwright.config.mjs'], {
      cwd: path.dirname(fileURLToPath(import.meta.url)),
      env: { ...process.env, DBPILOT_ACCEPTANCE_PHASE: phase, ACCEPTANCE_STATE_FILE: environment.ACCEPTANCE_STATE_FILE },
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const output = { stdout: '', stderr: '' };
    const append = (name, chunk) => {
      if (output[name].length < 1_000_000) output[name] += chunk.toString('utf8').slice(0, 1_000_000 - output[name].length);
    };
    child.stdout.on('data', (chunk) => append('stdout', chunk));
    child.stderr.on('data', (chunk) => append('stderr', chunk));
    child.on('error', () => reject(new Error('acceptance phase process could not start')));
    const timer = setTimeout(() => child.kill('SIGTERM'), 240_000);
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ exitCode: signal ? 124 : (code ?? 1), ...output });
    });
  });
}

function httpsJSON(url, ca, { method = 'GET', headers = {}, body } = {}) {
  const encoded = body === undefined ? undefined : Buffer.from(JSON.stringify(body), 'utf8');
  return new Promise((resolve, reject) => {
    const request = https.request(url, {
      method, ca, timeout: 10_000,
      headers: {
        Accept: 'application/json', ...headers,
        ...(encoded === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': String(encoded.length) }),
      },
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > 2 * 1024 * 1024) response.destroy(new Error('communication response exceeded limit'));
        else chunks.push(chunk);
      });
      response.on('end', () => {
        try {
          resolve({ status: response.statusCode ?? 0, value: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
        } catch {
          reject(new Error(`communication JSON response was invalid with status ${response.statusCode ?? 0}`));
        }
      });
    });
    request.on('timeout', () => request.destroy(new Error('communication HTTPS request timed out')));
    request.on('error', () => reject(new Error('communication HTTPS request failed')));
    if (encoded !== undefined) request.write(encoded);
    request.end();
  });
}

function requiredEnvironment(names) {
  const result = {};
  for (const name of names) {
    const value = process.env[name]?.trim();
    if (!value) throw new Error(`required communication environment is missing: ${name}`);
    result[name] = value;
  }
  return result;
}

const mainPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (process.env.NODE_TEST_CONTEXT === undefined && mainPath === fileURLToPath(import.meta.url)) {
  process.exitCode = await commandMain(process.argv.slice(2));
}
