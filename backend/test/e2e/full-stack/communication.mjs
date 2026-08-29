import { spawn } from 'node:child_process';
import { readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PHASES = new Set(['normal', 'post-restart', 'unauthorized', 'rogue']);
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

    if (phase === 'rogue') {
      const previous = validatePhaseState(await requiredFunction(dependencies.readState, 'phase state reader')());
      const observation = validateObservation(await requiredFunction(dependencies.observe, 'communication observer')(previous));
      const rogueResult = { ...dependencies.rogueResult, inventory: observation.inventory };
      assertRogueAgentRejected(rogueResult);
      if (!validTimestamp(rogueResult.observedAt)) throw new Error('rogue Agent observation timestamp is invalid');
      const field = rogueResult.kind === 'untrusted' ? 'rogue_untrusted_verified_at' : 'rogue_mismatch_verified_at';
      const state = Object.freeze({ ...previous, [field]: rogueResult.observedAt });
      await requiredFunction(dependencies.writeState, 'phase state writer')(state);
      return state;
    }

    const previous = validatePhaseState(await requiredFunction(dependencies.readState, 'phase state reader')());
    const faultWindow = validateFaultWindow(dependencies.faultWindow);
    let lastObservation;
    let observation;
    try {
      observation = await waitForObservation(
        dependencies,
        (candidate) => {
          lastObservation = candidate;
          return postRestartAdvanced(previous, candidate);
        },
        'post-restart communication state did not advance',
        previous,
      );
    } catch (error) {
      if (lastObservation) throw new Error(`${String(error?.message ?? error)}: ${postRestartDiagnostic(previous, lastObservation)}`);
      throw error;
    }
    const state = Object.freeze({
      ...mergeObservation(previous, observation),
      controlplane_stopped_at: faultWindow.stoppedAt,
      controlplane_restarted_at: faultWindow.restartedAt,
      pre_restart_metric_sample_at: previous.metric_sample_at,
      post_restart_metric_sample_at: observation.metric_sample_at,
      pre_restart_agent_control_heartbeat_at: previous.agent_control_heartbeat_at,
      post_restart_agent_control_heartbeat_at: observation.agent_control_heartbeat_at,
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
} = {}) {
  if (typeof requestJSON !== 'function' || ![tenantID, projectID, onlineAgentID, offlineAgentID].every(validIdentifier)) {
    throw new Error('runtime communication observation input is invalid');
  }
  const scopePath = `/api/v1/tenants/${encodeURIComponent(tenantID)}/projects/${encodeURIComponent(projectID)}`;
  const [targets, instances] = await Promise.all([
    requestJSON(`${scopePath}/inspection-targets?limit=100`),
    requestJSON(`${scopePath}/monitoring/instances?limit=100`),
  ]);
  const instance = (instances?.items ?? []).find((item) => item?.agent_id === onlineAgentID || item?.id === onlineAgentID);
  const inventory = Array.isArray(targets?.items) ? targets.items.map((item) => ({
    agent_id: String(item?.agent_id ?? ''),
    connectivity: String(item?.connectivity ?? ''),
    capabilities: Array.isArray(item?.capabilities) ? item.capabilities.map(String) : [],
    agent_control_heartbeat_at: item?.agent_control_heartbeat_at,
  })) : [];
  const onlineTarget = inventory.find((item) => item.agent_id === onlineAgentID);

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
    metric_sample_at: canonicalTimestamp(instance?.last_sample_at, 'metric_sample_at'),
    agent_control_heartbeat_at: canonicalTimestamp(onlineTarget?.agent_control_heartbeat_at, 'agent_control_heartbeat_at', onlineTarget?.connectivity),
    report_count: reportCount,
    finding_count: findingCount,
    audit_count: auditCount,
    terminal_command_id: terminalCommandID,
  });
}

export function assertRogueAgentRejected(result) {
  if (!result || !['untrusted', 'mismatch'].includes(result.kind)) throw new Error('rogue Agent result is invalid');
  if (!Array.isArray(result.inventory) || !Number.isInteger(result.exitCode) || typeof result.timedOut !== 'boolean') throw new Error('rogue Agent result is invalid');
  if ((result.timedOut && result.exitCode !== 124) || (!result.timedOut && result.exitCode === 0)) throw new Error('rogue Agent process result is invalid');
  const requiredIDs = result.kind === 'untrusted' ? ['agent-untrusted'] : ['agent-claimed-id', 'agent-certificate-id'];
  for (const agentID of requiredIDs) {
    const matches = result.inventory.filter((target) => target?.agent_id === agentID);
    if (matches.length !== 1 || matches[0].connectivity !== 'offline') throw new Error('rogue Agent target is not authoritatively offline');
  }
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  const expected = result.kind === 'untrusted'
    ? /(?:x509:\s*certificate signed by unknown authority|authentication handshake failed[^\n]*unknown authority|tls[^\n]*(?:failed to verify certificate|unknown certificate authority)|remote error:\s*tls:\s*certificate required)/i
    : /code\s*=\s*PermissionDenied[^\n]*(?:Hello Agent ID[^\n]*verified SPIFFE identity|SPIFFE[^\n]*mismatch)/i;
  if (!expected.test(output)) throw new Error(`rogue ${result.kind} Agent rejection evidence is missing`);
}

async function waitForObservation(dependencies, predicate, timeoutMessage, state) {
  const observe = requiredFunction(dependencies.observe, 'communication observer');
  const wait = dependencies.wait ?? defaultWait;
  const maxAttempts = positiveInteger(dependencies.maxAttempts, 60);
  let lastError = '';
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      const observation = validateObservation(await observe(state));
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
  const rogueOffline = ['agent-untrusted', 'agent-claimed-id', 'agent-certificate-id'].every((agentID) => (
    observation.inventory.filter((agent) => agent.agent_id === agentID && agent.connectivity === 'offline').length === 1
  ));
  return observation.inventory.length === 5
    && online?.connectivity === 'online'
    && online.capabilities.includes(REQUIRED_CAPABILITY)
    && offline?.connectivity === 'offline'
    && rogueOffline;
}

function postRestartAdvanced(previous, observation) {
  return Object.values(postRestartChecks(previous, observation)).every(Boolean);
}

function postRestartDiagnostic(previous, observation) {
  return Object.entries(postRestartChecks(previous, observation)).map(([name, value]) => `${name}=${value}`).join(' ');
}

function postRestartChecks(previous, observation) {
  return {
    ready: communicationReady(observation),
    metric_advanced: Date.parse(observation.metric_sample_at) > Date.parse(previous.metric_sample_at),
    heartbeat_advanced: Date.parse(observation.agent_control_heartbeat_at) > Date.parse(previous.agent_control_heartbeat_at),
    report_unchanged: observation.report_count === previous.report_count,
    findings_unchanged: observation.finding_count === previous.finding_count,
    audits_unchanged: observation.audit_count === previous.audit_count,
    terminal_command_match: observation.terminal_command_id === previous.journal_command_id,
  };
}

function mergeObservation(state, observation) {
  return Object.freeze({
    ...state,
    metric_sample_at: observation.metric_sample_at,
    agent_control_heartbeat_at: observation.agent_control_heartbeat_at,
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
  if (value.target_count !== 2 || value.artifact_count !== 2) throw new Error('browser phase counters are invalid');
  return Object.freeze({
    ...Object.fromEntries(['version', ...required].map((name) => [name, value[name]])),
    target_count: value.target_count,
    artifact_count: value.artifact_count,
  });
}

function validatePhaseState(value) {
  const state = validateBrowserState(value);
  for (const name of ['metric_sample_at', 'agent_control_heartbeat_at']) {
    if (!validTimestamp(value[name])) throw new Error('communication phase timestamp is invalid');
  }
  for (const name of ['report_count', 'finding_count', 'audit_count']) {
    if (!Number.isSafeInteger(value[name]) || value[name] < 0) throw new Error('communication phase counter is invalid');
  }
  const result = { ...state, ...Object.fromEntries([
    'metric_sample_at', 'agent_control_heartbeat_at', 'report_count', 'finding_count', 'audit_count',
  ].map((name) => [name, value[name]])) };
  for (const name of [
    'controlplane_stopped_at', 'controlplane_restarted_at',
    'pre_restart_metric_sample_at', 'post_restart_metric_sample_at',
    'pre_restart_agent_control_heartbeat_at', 'post_restart_agent_control_heartbeat_at',
    'rogue_untrusted_verified_at', 'rogue_mismatch_verified_at',
  ]) {
    if (value[name] !== undefined) {
      if (!validTimestamp(value[name])) throw new Error('communication phase timestamp is invalid');
      result[name] = value[name];
    }
  }
  return Object.freeze(result);
}

function validateObservation(value) {
  if (!value || !Array.isArray(value.inventory)) throw new Error('communication observation is invalid');
  const inventory = value.inventory.map((agent) => {
    if (!agent || !validIdentifier(agent.agent_id) || !['online', 'offline'].includes(agent.connectivity) || !Array.isArray(agent.capabilities)) {
      throw new Error('Agent communication observation is invalid');
    }
    return { agent_id: agent.agent_id, connectivity: agent.connectivity, capabilities: agent.capabilities.map(String) };
  });
  if (!validTimestamp(value.metric_sample_at) || !validTimestamp(value.agent_control_heartbeat_at)) throw new Error('communication observation timestamp is invalid');
  for (const name of ['report_count', 'finding_count', 'audit_count']) {
    if (!Number.isSafeInteger(value[name]) || value[name] < 0) throw new Error('communication observation counter is invalid');
  }
  if (!validIdentifier(value.terminal_command_id)) throw new Error('terminal command observation is invalid');
  return Object.freeze({ ...value, inventory });
}

async function requireProcessSuccess(result) {
  if (!result || result.exitCode !== 0) {
    const diagnostic = `${result?.stdout ?? ''}\n${result?.stderr ?? ''}`.trim().slice(-64_000);
    throw new Error(diagnostic ? `acceptance phase process failed: ${diagnostic}` : 'acceptance phase process failed');
  }
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

function canonicalTimestamp(value, name, connectivity) {
  if (!['metric_sample_at', 'agent_control_heartbeat_at'].includes(name) || !validTimestamp(value)) {
    const suffix = name === 'agent_control_heartbeat_at' ? ` connectivity=${['online', 'offline'].includes(connectivity) ? connectivity : 'unknown'}` : '';
    throw new Error(`runtime ${['metric_sample_at', 'agent_control_heartbeat_at'].includes(name) ? name : 'communication'} timestamp is invalid${suffix}`);
  }
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
    const runtime = await createRuntimeDependencies(phase);
    sensitiveValues = runtime.sensitiveValues;
    await runCommunicationPhase(phase, runtime);
    process.stdout.write(`communication phase ${phase} passed\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`${redact(String(error?.message ?? error), sensitiveValues)}\n`);
    return 1;
  }
}

async function createRuntimeDependencies(phase) {
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
  const faultWindow = phase === 'post-restart' ? validateFaultWindow({
    stoppedAt: process.env.CONTROLPLANE_STOPPED_AT,
    restartedAt: process.env.CONTROLPLANE_RESTARTED_AT,
  }) : undefined;
  let rogueResult;
  if (phase === 'rogue') {
    const rogueEnvironment = requiredEnvironment(['ROGUE_KIND', 'ROGUE_EXIT_CODE', 'ROGUE_TIMED_OUT', 'ROGUE_LOG_FILE', 'ROGUE_OBSERVED_AT']);
    if (!path.isAbsolute(rogueEnvironment.ROGUE_LOG_FILE)) throw new Error('rogue Agent log path is invalid');
    const info = await stat(rogueEnvironment.ROGUE_LOG_FILE);
    if (!info.isFile() || info.size > 1_000_000) throw new Error('rogue Agent log is unavailable or oversized');
    const exitCode = Number(rogueEnvironment.ROGUE_EXIT_CODE);
    if (!Number.isInteger(exitCode) || !['true', 'false'].includes(rogueEnvironment.ROGUE_TIMED_OUT)) throw new Error('rogue Agent process result is invalid');
    rogueResult = {
      kind: rogueEnvironment.ROGUE_KIND, exitCode, timedOut: rogueEnvironment.ROGUE_TIMED_OUT === 'true',
      stderr: await readFile(rogueEnvironment.ROGUE_LOG_FILE, 'utf8'), observedAt: rogueEnvironment.ROGUE_OBSERVED_AT,
    };
  }
  return {
    sensitiveValues: [credential, accessToken],
    maxAttempts: 120,
    faultWindow,
    rogueResult,
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

function validateFaultWindow(value) {
  if (!value || !validTimestamp(value.stoppedAt) || !validTimestamp(value.restartedAt) || Date.parse(value.restartedAt) <= Date.parse(value.stoppedAt)) {
    throw new Error('control-plane outage window is invalid');
  }
  return Object.freeze({ stoppedAt: value.stoppedAt, restartedAt: value.restartedAt });
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
