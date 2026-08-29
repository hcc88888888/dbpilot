import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import {
  assertRogueAgentRejected,
  collectRuntimeObservation,
  runCommunicationPhase,
} from '../../backend/test/e2e/full-stack/communication.mjs';

const baseState = Object.freeze({
  version: 1,
  tenant_id: 'tenant-acceptance',
  project_id: 'project-acceptance',
  online_agent_id: 'agent-online',
  offline_agent_id: 'agent-offline',
  policy_id: 'policy-1',
  run_id: 'run-1',
  job_id: 'job-1',
  report_id: 'report-1',
  online_command_id: 'command-online',
  offline_command_id: 'command-offline',
  journal_command_id: 'command-online',
  audit_correlation: 'correlation-1',
});

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const communicationScript = path.join(repositoryRoot, 'backend', 'test', 'e2e', 'full-stack', 'communication.mjs');
const composeFile = path.join(repositoryRoot, 'backend', 'docker', 'full-stack', 'docker-compose.yml');
const runnerDockerfile = path.join(repositoryRoot, 'backend', 'docker', 'full-stack', 'runner.Dockerfile');

test('communication command rejects unknown phases before reading runtime credentials', () => {
  const environment = { ...process.env };
  delete environment.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, [communicationScript, 'unknown'], { cwd: repositoryRoot, encoding: 'utf8', env: environment });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /communication phase is invalid/);
  assert.doesNotMatch(result.stderr, /credential|token|private key/i);
});

test('Compose wires verifier-selected runner/assertion phases and isolated bounded rogue state', async () => {
  const configured = spawnSync('docker', ['compose', '-f', composeFile, '--profile', '*', 'config', '--format', 'json'], {
    cwd: repositoryRoot, encoding: 'utf8',
  });
  assert.equal(configured.status, 0, configured.stderr || configured.stdout);
  const config = JSON.parse(configured.stdout);
  const runner = config.services['acceptance-runner'];
  assert.equal(runner.environment.ACCEPTANCE_STATE_FILE, '/acceptance/state/phase-state.json');
  assert.notEqual(runner.volumes.find((mount) => mount.target === '/acceptance/state').read_only, true);
  const dockerfile = await readFile(runnerDockerfile, 'utf8');
  assert.match(dockerfile, /COPY .*communication\.mjs/);
  assert.match(dockerfile, /ENTRYPOINT \["node", "communication\.mjs"\]/);

  const rogueMountSources = [];
  for (const name of ['rogue-untrusted', 'rogue-mismatch']) {
    const service = config.services[name];
    assert.match(service.command.join(' '), /timeout .*30s .*dbpilot-agent/);
    const dataMount = service.volumes.find((mount) => mount.target.includes(`/agent-${name === 'rogue-untrusted' ? 'untrusted' : 'mismatch'}`) && !mount.read_only);
    assert.ok(dataMount, `${name} must have isolated writable state`);
    rogueMountSources.push(dataMount.source);
  }
  assert.equal(new Set(rogueMountSources).size, 2);
  const bootstrap = config.services.bootstrap;
  for (const [index, target] of ['/volumes/rogue-untrusted-data', '/volumes/rogue-mismatch-data'].entries()) {
    const mount = bootstrap.volumes.find((candidate) => candidate.target === target);
    assert.equal(mount.source, rogueMountSources[index]);
    assert.notEqual(mount.read_only, true);
    assert.match(bootstrap.command.join(' '), new RegExp(`chown[^\\n]*${target.replaceAll('/', '\\/')}`));
  }
  const assertions = config.services.assertions;
  assert.match(assertions.command.join(' '), /DBPILOT_ASSERTION_PHASE/);
  assert.match(assertions.command.join(' '), /journal/);
  assert.match(assertions.command.join(' '), /replay/);
  assert.notEqual(assertions.volumes.find((mount) => mount.target === '/acceptance/state').read_only, true);
});

test('normal phase waits for Hello-derived online host.v1 readiness and records distinct metric and control heartbeats', async () => {
  const events = [];
  const observations = [
    observation({ capabilities: [], agentControlHeartbeatAt: undefined }),
    observation({ capabilities: ['collect_now.host.v1'] }),
    observation({ capabilities: ['collect_now.host.v1'] }),
  ];
  let written;

  const result = await runCommunicationPhase('normal', {
    observe: async () => {
      events.push('observe');
      return observations.shift();
    },
    runProcess: async (phase) => {
      events.push(`process:${phase}`);
      return { exitCode: 0, state: baseState, stdout: '', stderr: '' };
    },
    writeState: async (state) => { written = state; },
    wait: async () => {},
    maxAttempts: 2,
  });

  assert.deepEqual(events, ['observe', 'observe', 'process:normal', 'observe']);
  assert.equal(result.online_agent_id, 'agent-online');
  assert.equal(result.metric_sample_at, '2026-08-29T04:00:03.000Z');
  assert.equal(result.agent_control_heartbeat_at, '2026-08-29T04:00:04.000Z');
  assert.equal('accepted_at' in result, false);
  assert.equal('spool_observed_count' in result, false);
  assert.deepEqual(written, result);
});

test('normal phase never starts browser work without online host.v1 readiness', async () => {
  let processCalls = 0;
  await assert.rejects(
    runCommunicationPhase('normal', {
      observe: async () => observation({ capabilities: [] }),
      runProcess: async () => { processCalls += 1; return { exitCode: 0, state: baseState }; },
      writeState: async () => {},
      wait: async () => {},
      maxAttempts: 2,
    }),
    /Agent communication readiness timed out/,
  );
  assert.equal(processCalls, 0);
});

test('post-restart rejects unchanged metric or AgentControl heartbeat state', async () => {
  const previous = {
    ...baseState,
    metric_sample_at: '2026-08-29T04:00:03.000Z',
    agent_control_heartbeat_at: '2026-08-29T04:00:04.000Z',
    report_count: 1,
    finding_count: 13,
    audit_count: 4,
  };
  await assert.rejects(
    runCommunicationPhase('post-restart', {
      observe: async () => observation({
        capabilities: ['collect_now.host.v1'],
        metricSampleAt: previous.metric_sample_at,
        agentControlHeartbeatAt: previous.agent_control_heartbeat_at,
      }),
      readState: async () => previous,
      writeState: async () => {},
      wait: async () => {},
      maxAttempts: 1,
      faultWindow: { stoppedAt: '2026-08-29T04:00:10.000Z', restartedAt: '2026-08-29T04:01:00.000Z' },
    }),
    /post-restart communication state did not advance/,
  );
});

test('post-restart rejects missing or reversed verifier stop/restart boundaries', async () => {
  const previous = {
    ...baseState,
    metric_sample_at: '2026-08-29T04:00:03.000Z', agent_control_heartbeat_at: '2026-08-29T04:00:04.000Z',
    report_count: 1, finding_count: 13, audit_count: 4,
  };
  for (const faultWindow of [undefined, { stoppedAt: '2026-08-29T04:01:00.000Z', restartedAt: '2026-08-29T04:00:10.000Z' }]) {
    await assert.rejects(runCommunicationPhase('post-restart', {
      observe: async () => observation({ metricSampleAt: '2026-08-29T04:01:03.000Z', agentControlHeartbeatAt: '2026-08-29T04:01:04.000Z' }),
      readState: async () => previous,
      writeState: async () => {},
      wait: async () => {},
      maxAttempts: 1,
      faultWindow,
    }), /control-plane outage window is invalid/);
  }
});

test('post-restart records verifier outage boundaries and distinct advanced metric/control liveness', async () => {
  const previous = {
    ...baseState,
    metric_sample_at: '2026-08-29T04:00:03.000Z', agent_control_heartbeat_at: '2026-08-29T04:00:04.000Z',
    report_count: 1, finding_count: 13, audit_count: 4,
  };
  let written;
  const result = await runCommunicationPhase('post-restart', {
    observe: async () => observation({
      capabilities: ['collect_now.host.v1'],
      metricSampleAt: '2026-08-29T04:01:03.000Z', agentControlHeartbeatAt: '2026-08-29T04:01:04.000Z',
      reportCount: 1, findingCount: 13, auditCount: 4,
      terminalCommandID: 'command-online',
    }),
    readState: async () => previous,
    writeState: async (state) => { written = state; },
    wait: async () => {},
    maxAttempts: 1,
    faultWindow: { stoppedAt: '2026-08-29T04:00:10.000Z', restartedAt: '2026-08-29T04:01:00.000Z' },
  });
  assert.equal(result.journal_command_id, previous.journal_command_id);
  assert.equal(result.controlplane_stopped_at, '2026-08-29T04:00:10.000Z');
  assert.equal(result.controlplane_restarted_at, '2026-08-29T04:01:00.000Z');
  assert.equal(result.pre_restart_metric_sample_at, previous.metric_sample_at);
  assert.equal(result.post_restart_metric_sample_at, '2026-08-29T04:01:03.000Z');
  assert.equal(result.pre_restart_agent_control_heartbeat_at, previous.agent_control_heartbeat_at);
  assert.equal(result.post_restart_agent_control_heartbeat_at, '2026-08-29T04:01:04.000Z');
  assert.deepEqual(written, result);
});

test('post-restart rejects online Agent and newer metrics when AgentControl heartbeat is unchanged or missing', async () => {
  const previous = {
    ...baseState,
    metric_sample_at: '2026-08-29T04:00:03.000Z', agent_control_heartbeat_at: '2026-08-29T04:00:04.000Z',
    report_count: 1, finding_count: 13, audit_count: 4,
  };
  for (const heartbeat of [previous.agent_control_heartbeat_at, undefined]) {
    await assert.rejects(runCommunicationPhase('post-restart', {
      observe: async () => observation({ metricSampleAt: '2026-08-29T04:01:03.000Z', agentControlHeartbeatAt: heartbeat }),
      readState: async () => previous,
      writeState: async () => {},
      wait: async () => {},
      maxAttempts: 1,
      faultWindow: { stoppedAt: '2026-08-29T04:00:10.000Z', restartedAt: '2026-08-29T04:01:00.000Z' },
    }), /post-restart communication state did not advance/);
  }
});

test('unauthorized phase runs only the bounded negative browser process', async () => {
  const phases = [];
  await runCommunicationPhase('unauthorized', {
    runProcess: async (phase) => { phases.push(phase); return { exitCode: 0, stdout: '', stderr: '' }; },
  });
  assert.deepEqual(phases, ['unauthorized']);
});

test('rogue rejection parser requires exact x509 or PermissionDenied SPIFFE mismatch evidence', () => {
  assert.doesNotThrow(() => assertRogueAgentRejected({
    kind: 'untrusted', timedOut: true, exitCode: 124,
    stderr: 'transport: authentication handshake failed: certificate signed by unknown authority',
    inventory: rogueTargets(),
  }));
  assert.doesNotThrow(() => assertRogueAgentRejected({
    kind: 'mismatch', timedOut: false, exitCode: 1,
    stderr: 'rpc error: code = PermissionDenied desc = Hello Agent ID does not match the verified SPIFFE identity',
    inventory: rogueTargets(),
  }));
  assert.throws(() => assertRogueAgentRejected({
    kind: 'untrusted', timedOut: true, exitCode: 124, stderr: 'TLS client initialized with certificate', inventory: rogueTargets(),
  }), /rejection evidence is missing/);
  assert.throws(() => assertRogueAgentRejected({
    kind: 'mismatch', timedOut: true, exitCode: 124, stderr: 'rpc error: code = PermissionDenied', inventory: rogueTargets(),
  }), /rejection evidence is missing/);
  assert.throws(() => assertRogueAgentRejected({
    kind: 'mismatch', timedOut: true, exitCode: 124, stderr: 'code = PermissionDenied', inventory: rogueTargets().map((target) => target.agent_id === 'agent-claimed-id' ? { ...target, connectivity: 'online' } : target),
  }), /rogue Agent target is not authoritatively offline/);
});

test('rogue phase consumes structured process evidence and persists only verified timestamps', async () => {
  const previous = {
    ...baseState,
    metric_sample_at: '2026-08-29T04:01:03.000Z', agent_control_heartbeat_at: '2026-08-29T04:01:04.000Z',
    report_count: 1, finding_count: 13, audit_count: 4,
  };
  let written;
  const result = await runCommunicationPhase('rogue', {
    observe: async () => observation(),
    readState: async () => previous,
    writeState: async (state) => { written = state; },
    rogueResult: {
      kind: 'mismatch', timedOut: false, exitCode: 1,
      stderr: 'rpc error: code = PermissionDenied desc = Hello Agent ID does not match the verified SPIFFE identity',
      observedAt: '2026-08-29T04:02:00.000Z',
    },
  });
  assert.equal(result.rogue_mismatch_verified_at, '2026-08-29T04:02:00.000Z');
  assert.equal('stderr' in result, false);
  assert.deepEqual(written, result);
});

test('communication failures redact configured credentials and bearer values', async () => {
  const secret = 'credential-value-that-must-not-leak';
  await assert.rejects(
    runCommunicationPhase('normal', {
      observe: async () => { throw new Error(`Bearer ${secret} failed`); },
      runProcess: async () => ({ exitCode: 0, state: baseState }),
      writeState: async () => {},
      wait: async () => {},
      maxAttempts: 1,
      sensitiveValues: [secret],
    }),
    (error) => !String(error).includes(secret) && /\[REDACTED\]/.test(String(error)),
  );
});

test('runtime observation keeps authenticated metric liveness separate from AgentControl heartbeat', async () => {
  const requests = [];
  const responseBySuffix = new Map([
    ['/inspection-targets?limit=100', { items: [
      { agent_id: 'agent-online', connectivity: 'online', capabilities: ['collect_now.host.v1'], agent_control_heartbeat_at: '2026-08-29T04:00:04Z' },
      { agent_id: 'agent-offline', connectivity: 'offline', capabilities: [] },
      ...rogueTargets(),
    ] }],
    ['/monitoring/instances?limit=100', { items: [
      { id: 'agent-online', agent_id: 'agent-online', last_sample_at: '2026-08-29T04:00:03Z', last_heartbeat_at: '2099-01-01T00:00:00Z' },
    ] }],
    ['/inspection-reports/report-1', { id: 'report-1', findings: Array.from({ length: 13 }, (_, index) => ({ item_id: `item-${index}` })), references: { commands: [
      { command_id: 'command-online' }, { command_id: 'command-offline' },
    ] } }],
    ['/audit-events?limit=100', { items: [
      { job_id: 'job-1' }, { command_id: 'command-online' }, { command_id: 'command-offline' }, { resource_id: 'report-1' },
    ] }],
  ]);
  const result = await collectRuntimeObservation({
    state: baseState,
    requestJSON: async (path) => {
      requests.push(path);
      const suffix = [...responseBySuffix.keys()].find((candidate) => path.endsWith(candidate) || path.includes(candidate));
      if (!suffix) throw new Error(`unexpected request ${path}`);
      return responseBySuffix.get(suffix);
    },
    tenantID: 'tenant-acceptance', projectID: 'project-acceptance', onlineAgentID: 'agent-online', offlineAgentID: 'agent-offline',
  });
  assert.equal(requests.length, 4);
  assert.equal(requests.some((request) => request.includes('/monitoring/series')), false);
  assert.equal(result.metric_sample_at, '2026-08-29T04:00:03Z');
  assert.equal(result.agent_control_heartbeat_at, '2026-08-29T04:00:04Z');
  assert.equal(result.inventory.length, 5);
  assert.equal(result.report_count, 1);
  assert.equal(result.finding_count, 13);
  assert.equal(result.audit_count, 4);
  assert.equal(result.terminal_command_id, 'command-online');
});

function observation({
  capabilities = ['collect_now.host.v1'],
  metricSampleAt = '2026-08-29T04:00:03.000Z',
  agentControlHeartbeatAt = '2026-08-29T04:00:04.000Z',
  reportCount = 1,
  findingCount = 13,
  auditCount = 4,
  terminalCommandID = 'command-online',
} = {}) {
  return {
    inventory: [
      { agent_id: 'agent-online', connectivity: 'online', capabilities, agent_control_heartbeat_at: agentControlHeartbeatAt },
      { agent_id: 'agent-offline', connectivity: 'offline', capabilities: [] },
      ...rogueTargets(),
    ],
    metric_sample_at: metricSampleAt,
    agent_control_heartbeat_at: agentControlHeartbeatAt,
    report_count: reportCount,
    finding_count: findingCount,
    audit_count: auditCount,
    terminal_command_id: terminalCommandID,
  };
}

function rogueTargets() {
  return ['agent-untrusted', 'agent-claimed-id', 'agent-certificate-id'].map((agent_id) => ({ agent_id, connectivity: 'offline', capabilities: [] }));
}
