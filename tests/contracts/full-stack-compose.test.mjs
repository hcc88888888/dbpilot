import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const composeFile = join(repoRoot, 'backend', 'docker', 'full-stack', 'docker-compose.yml');
const nginxFile = join(repoRoot, 'backend', 'docker', 'full-stack', 'nginx.conf');
const runnerFile = join(repoRoot, 'backend', 'docker', 'full-stack', 'runner.Dockerfile');
const bootstrapFile = join(repoRoot, 'backend', 'test', 'fixtures', 'fullstack', 'bootstrap.go');
const runnerPackageFile = join(repoRoot, 'backend', 'test', 'e2e', 'full-stack', 'package.json');
const runnerLockFile = join(repoRoot, 'backend', 'test', 'e2e', 'full-stack', 'package-lock.json');

const serviceNames = [
  'acceptance-runner',
  'agent',
  'assertions',
  'asset-builder',
  'bootstrap',
  'controlplane',
  'frontend',
  'oidc',
  'postgres',
  'rogue-mismatch',
  'rogue-untrusted',
];

const volumeNames = [
  'acceptance-agent-data',
  'acceptance-artifacts',
  'acceptance-bin',
  'acceptance-config',
  'acceptance-go-cache',
  'acceptance-runner-node-modules',
  'acceptance-secrets',
  'acceptance-state',
];

function loadCompose() {
  const result = spawnSync('docker', ['compose', '-f', composeFile, '--profile', '*', 'config', '--format', 'json'], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout);
}

function mountAt(service, target) {
  return (service.volumes ?? []).find((volume) => volume.target === target);
}

function commandText(service) {
  return [...(service.entrypoint ?? []), ...(service.command ?? [])].join(' ');
}

function docker(args, env = {}, timeout = 300_000) {
  return spawnSync('docker', args, {
    cwd: repoRoot,
    encoding: 'utf8',
    env: { ...process.env, ...env },
    timeout,
  });
}

function lines(value) {
  return value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function assertExactRunnerPackageContract(packageMetadata, lock, imageVersion) {
  const lockRoot = lock.packages?.[''];
  assert.ok(lockRoot, 'package-lock.json must contain its root package entry');
  for (const group of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const expected = group === 'devDependencies' ? { '@playwright/test': '1.62.0' } : {};
    assert.deepEqual(packageMetadata[group] ?? {}, expected, `package.json ${group}`);
    assert.deepEqual(lockRoot[group] ?? {}, expected, `package-lock root ${group}`);
  }
  assert.equal(packageMetadata.scripts?.postinstall, undefined);
  assert.equal(lock.packages?.['node_modules/@playwright/test']?.version, '1.62.0');
  assert.equal(imageVersion, '1.62.0');
}

test('Compose resolves the exact isolated full-stack service, image, network, and volume topology', () => {
  const config = loadCompose();
  assert.deepEqual(Object.keys(config.services).sort(), serviceNames);
  assert.deepEqual(Object.keys(config.volumes).sort(), volumeNames);
  assert.deepEqual(Object.keys(config.networks).sort(), ['acceptance', 'builder-egress']);
  assert.equal(config.networks.acceptance.internal, true);
  assert.equal(config.networks.acceptance.driver, 'bridge');
  assert.notEqual(config.networks['builder-egress'].internal, true);
  assert.equal(config.networks['builder-egress'].driver, 'bridge');

  const expectedImages = {
    'asset-builder': 'golang:1.27.0-bookworm',
    bootstrap: 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1',
    postgres: 'postgres:16-alpine',
    oidc: 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1',
    controlplane: 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1',
    agent: 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1',
    frontend: 'nginx:1.29.1-alpine',
    'rogue-untrusted': 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1',
    'rogue-mismatch': 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1',
    assertions: 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1',
  };
  for (const [name, image] of Object.entries(expectedImages)) {
    assert.equal(config.services[name].image, image, `${name} must use the approved exact image`);
    if (image === 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1') {
      assert.equal(config.services[name].platform, 'linux/amd64', `${name} must select the approved amd64 Kylin manifest`);
    }
  }
  assert.equal(config.services['acceptance-runner'].build.dockerfile, 'backend/docker/full-stack/runner.Dockerfile');

  for (const [name, service] of Object.entries(config.services)) {
    const expectedNetworks = name === 'asset-builder' ? ['builder-egress'] : ['acceptance'];
    assert.deepEqual(Object.keys(service.networks), expectedNetworks, `${name} must use only its approved network`);
    assert.equal(service.labels['dbpilot.verifier'], 'full-stack-compose');
    assert.ok(service.labels['dbpilot.run'], `${name} must carry a run ownership label`);
    assert.equal(service.restart, 'no');
    assert.ok(service.cpus, `${name} must have a CPU limit`);
    assert.ok(service.mem_limit, `${name} must have a memory limit`);
    assert.ok(service.pids_limit, `${name} must have a PID limit`);
  }
  for (const resource of [...Object.values(config.networks), ...Object.values(config.volumes)]) {
    assert.equal(resource.labels['dbpilot.verifier'], 'full-stack-compose');
    assert.ok(resource.labels['dbpilot.run']);
  }
});

test('builder uses a non-login shell and exact static linux amd64 settings to build only the three approved binaries', () => {
  const builder = loadCompose().services['asset-builder'];
  assert.deepEqual(builder.entrypoint, ['/bin/sh', '-ec']);
  assert.equal(builder.environment.CGO_ENABLED, '0');
  assert.equal(builder.environment.GOOS, 'linux');
  assert.equal(builder.environment.GOARCH, 'amd64');
  assert.equal(builder.environment.GOAMD64, 'v1');
  assert.equal(builder.environment.GOTMPDIR, '/go-cache/tmp');
  assert.ok(Number(builder.cpus) >= 4, 'production dependency compilation needs a bounded four-CPU builder');
  assert.ok(Number(builder.mem_limit) >= 4 * 1024 ** 3, 'production dependency compilation needs a bounded 4 GiB builder');
  assert.equal(builder.working_dir, '/workspace/backend');
  assert.equal(mountAt(builder, '/workspace').read_only, true);
  assert.notEqual(mountAt(builder, '/acceptance/bin').read_only, true);
  assert.notEqual(mountAt(builder, '/go-cache').read_only, true);

  const command = commandText(builder);
  assert.match(command, /go build .*\.\/cmd\/controlplane/);
  assert.match(command, /go build .*\.\/cmd\/agent/);
  assert.match(command, /go build .*\.\/test\/fixtures\/fullstack/);
  assert.match(command, /\/acceptance\/bin\/dbpilot-controlplane/);
  assert.match(command, /\/acceptance\/bin\/dbpilot-agent/);
  assert.match(command, /\/acceptance\/bin\/dbpilot-fullstack-fixture/);
});

test('opt-in clean-cache builder produces all binaries and removes its exact labelled project resources', {
  skip: process.env.DBPILOT_FULL_STACK_BUILDER_PROBE !== '1',
  timeout: 1_260_000,
}, () => {
  const project = `dbpilot-t2-builder-${process.pid}-${Date.now().toString(36)}`.toLowerCase();
  const env = { DBPILOT_ACCEPTANCE_RUN_ID: project };
  const compose = ['compose', '-p', project, '-f', composeFile];
  const recorded = { containers: [], networks: [], volumes: [] };
  let primaryError;

  try {
    const up = docker([...compose, 'up', '--no-deps', '--pull', 'never', '--abort-on-container-exit', '--exit-code-from', 'asset-builder', 'asset-builder'], env, 1_200_000);
    assert.equal(up.status, 0, up.stderr || up.stdout);

    recorded.containers = lines(docker(['ps', '-aq', '--filter', `label=com.docker.compose.project=${project}`]).stdout);
    recorded.networks = lines(docker(['network', 'ls', '-q', '--filter', `label=com.docker.compose.project=${project}`]).stdout);
    recorded.volumes = lines(docker(['volume', 'ls', '-q', '--filter', `label=com.docker.compose.project=${project}`]).stdout);
    assert.equal(recorded.containers.length, 1);
    assert.equal(recorded.networks.length, 1);
    assert.deepEqual(recorded.volumes.sort(), [`${project}_acceptance-bin`, `${project}_acceptance-go-cache`]);

    for (const [kind, values] of Object.entries(recorded)) {
      for (const value of values) {
        const noun = kind === 'containers' ? 'container' : kind.slice(0, -1);
        const format = noun === 'container' ? '{{json .Config.Labels}}' : '{{json .Labels}}';
        const inspected = docker([noun, 'inspect', '--format', format, value]);
        assert.equal(inspected.status, 0, inspected.stderr);
        const labels = JSON.parse(inspected.stdout);
        assert.equal(labels['com.docker.compose.project'], project);
        assert.equal(labels['dbpilot.verifier'], 'full-stack-compose');
        assert.equal(labels['dbpilot.run'], project);
      }
    }

    const binaryVolume = `${project}_acceptance-bin`;
    const probeName = `${project}-output-probe`;
    const probe = docker([
      'run', '--rm', '--pull', 'never', '--name', probeName,
      '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
      '--volume', `${binaryVolume}:/acceptance/bin:ro`, '--entrypoint', '/bin/sh', 'golang:1.27.0-bookworm',
      '-ec', 'for binary in dbpilot-controlplane dbpilot-agent dbpilot-fullstack-fixture; do test -s "/acceptance/bin/$binary"; test -x "/acceptance/bin/$binary"; done',
    ]);
    assert.equal(probe.status, 0, probe.stderr || probe.stdout);
    const removedProbe = docker(['container', 'inspect', probeName]);
    assert.notEqual(removedProbe.status, 0, 'the --rm output probe container must be removed');
  } catch (error) {
    primaryError = error;
  }

  const cleanupErrors = [];
  const down = docker([...compose, 'down', '-v', '--remove-orphans', '--timeout', '10'], env);
  if (down.status !== 0) cleanupErrors.push(new Error(down.stderr || down.stdout));
  for (const [kind, values] of Object.entries(recorded)) {
    for (const value of values) {
      const noun = kind === 'containers' ? 'container' : kind.slice(0, -1);
      const inspected = docker([noun, 'inspect', value]);
      if (inspected.status === 0) cleanupErrors.push(new Error(`${noun} ${value} survived exact project cleanup`));
    }
  }
  for (const kind of ['container', 'network', 'volume']) {
    const command = kind === 'container' ? ['ps', '-aq'] : [kind, 'ls', '-q'];
    const remaining = docker([...command, '--filter', `label=com.docker.compose.project=${project}`]);
    if (remaining.status !== 0 || lines(remaining.stdout).length !== 0) {
      cleanupErrors.push(new Error(`${kind} cleanup audit failed for project ${project}`));
    }
  }

  if (primaryError || cleanupErrors.length > 0) {
    throw new AggregateError([...(primaryError ? [primaryError] : []), ...cleanupErrors], 'clean-cache builder probe failed');
  }
});

test('one-shot ownership initializers retain default CHOWN without adding capabilities', () => {
  const services = loadCompose().services;
  for (const name of ['asset-builder', 'bootstrap']) {
    assert.match(commandText(services[name]), /chown(?: -R)? 10001:10001/);
    assert.ok(!services[name].cap_drop.includes('ALL'), `${name} cannot drop CAP_CHOWN before transferring volume ownership`);
    assert.equal(services[name].cap_add, undefined);
  }
});

test('runtime mounts keep source, binaries, config, and secrets read-only while limiting writable named state', () => {
  const config = loadCompose();
  const writableTargets = {
    'asset-builder': ['/acceptance/bin', '/go-cache'],
    bootstrap: ['/volumes/config', '/volumes/secrets', '/volumes/state', '/volumes/artifacts', '/volumes/agent-data'],
    controlplane: ['/acceptance/state/artifacts'],
    agent: ['/acceptance/state/agent-online'],
    'acceptance-runner': ['/acceptance/artifacts', '/work/node_modules'],
  };

  for (const [name, service] of Object.entries(config.services)) {
    for (const mount of service.volumes ?? []) {
      if (mount.type === 'bind') {
        assert.equal(mount.read_only, true, `${name} bind mount ${mount.target} must be read-only`);
      }
      if (mount.type === 'volume' && !mount.read_only) {
        assert.ok((writableTargets[name] ?? []).includes(mount.target), `${name} has unexpected writable volume ${mount.target}`);
      }
    }
  }

  for (const name of ['oidc', 'controlplane', 'agent', 'rogue-untrusted', 'rogue-mismatch', 'assertions']) {
    assert.equal(config.services[name].user, '10001:10001');
    assert.equal(mountAt(config.services[name], '/acceptance/bin').read_only, true);
    assert.equal(mountAt(config.services[name], '/acceptance/config').read_only, true);
    assert.equal(mountAt(config.services[name], '/acceptance/secrets').read_only, true);
  }
});

test('only frontend publishes a Docker-assigned loopback port and runtime dependencies use completion or health conditions', () => {
  const config = loadCompose();
  for (const [name, service] of Object.entries(config.services)) {
    if (name === 'frontend') {
      assert.equal(service.ports.length, 1);
      assert.equal(service.ports[0].host_ip, '127.0.0.1');
      assert.equal(service.ports[0].target, 8443);
      assert.equal(service.ports[0].published, '0');
    } else {
      assert.equal(service.ports, undefined, `${name} must not publish a host port`);
    }
  }
  assert.ok(config.services.postgres.healthcheck);
  assert.ok(config.services.oidc.healthcheck);
  assert.ok(config.services.controlplane.healthcheck);
  assert.ok(config.services.frontend.healthcheck);
  assert.deepEqual(config.services.frontend.healthcheck.test, ['CMD', 'wget', '-q', '--spider', 'https://frontend:8443/healthz']);
  assert.doesNotMatch(config.services.frontend.healthcheck.test.join(' '), /ca-certificate|no-check-certificate/i);
  const frontendTrust = mountAt(config.services.frontend, '/etc/ssl/certs');
  const frontendConfig = mountAt(config.services.frontend, '/acceptance/config');
  assert.equal(frontendTrust.source, frontendConfig.source);
  assert.equal(frontendTrust.read_only, true);
  assert.equal(config.services.bootstrap.depends_on['asset-builder'].condition, 'service_completed_successfully');
  assert.equal(config.services.postgres.depends_on.bootstrap.condition, 'service_completed_successfully');
  assert.equal(config.services.oidc.depends_on.bootstrap.condition, 'service_completed_successfully');
  assert.equal(config.services.controlplane.depends_on.postgres.condition, 'service_healthy');
  assert.equal(config.services.controlplane.depends_on.oidc.condition, 'service_healthy');
  assert.equal(config.services.agent.depends_on.controlplane.condition, 'service_healthy');
  assert.equal(config.services.frontend.depends_on.controlplane.condition, 'service_healthy');
});

test('acceptance runner is verifier-controlled and encodes no false Agent readiness edge', () => {
  const runner = loadCompose().services['acceptance-runner'];
  assert.deepEqual(runner.profiles, ['acceptance-runner']);
  assert.equal(runner.depends_on, undefined);
});

test('Kylin production runtimes verify OS, architecture, and binary version before execution', () => {
  const services = loadCompose().services;
  for (const name of ['controlplane', 'agent', 'rogue-untrusted', 'rogue-mismatch']) {
    const command = commandText(services[name]);
    assert.match(command, /\/etc\/os-release/);
    assert.match(command, /ID.*kylin/);
    assert.match(command, /VERSION_ID.*V10/);
    assert.match(command, /uname -m/);
    assert.match(command, /x86_64/);
    assert.match(command, /dbpilot-(?:controlplane|agent) --version/);
    assert.match(command, /exec \/acceptance\/bin\/dbpilot-(?:controlplane|agent)/);
  }
});

test('Nginx serves the repository UI and verifies the same-origin HTTPS upstream without exposing OIDC', async () => {
  const nginx = await readFile(nginxFile, 'utf8');
  assert.match(nginx, /listen\s+8443\s+ssl/);
  assert.match(nginx, /ssl_certificate\s+\/acceptance\/config\/frontend\.pem/);
  assert.match(nginx, /ssl_certificate_key\s+\/acceptance\/secrets\/frontend-key\.pem/);
  assert.match(nginx, /ssl_protocols\s+TLSv1\.2\s+TLSv1\.3/);
  assert.match(nginx, /location\s*=\s*\/healthz/);
  assert.match(nginx, /root\s+\/srv\/dbpilot\/frontend/);
  assert.match(nginx, /location\s+\/api\//);
  assert.match(nginx, /proxy_pass\s+https:\/\/controlplane:8443/);
  assert.match(nginx, /proxy_ssl_verify\s+on/);
  assert.match(nginx, /proxy_ssl_server_name\s+on/);
  assert.match(nginx, /proxy_ssl_name\s+controlplane/);
  assert.match(nginx, /proxy_set_header\s+X-Forwarded-Proto\s+https/);
  assert.match(nginx, /proxy_ssl_trusted_certificate\s+\/acceptance\/config\/ca\.pem/);
  assert.match(nginx, /proxy_buffering\s+off/);
  assert.match(nginx, /client_max_body_size\s+\d+[km]/i);
  assert.match(nginx, /proxy_(?:connect|read|send)_timeout\s+\d+s/);
  for (const temporaryPath of ['client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi']) {
    assert.match(nginx, new RegExp(`${temporaryPath}_temp_path\\s+\\/tmp\\/`), `${temporaryPath} temp output must stay off the read-only root`);
  }
  assert.equal(nginx.match(/\/acceptance\/secrets\//g)?.length, 1, 'only the frontend TLS key may be read from secrets');
  assert.doesNotMatch(nginx, /oidc|location\s+[^\n]*\/token|proxy_pass[^\n]*\/token/i);
});

test('generated Artifact descriptor origin and path are served by the checked-in frontend proxy', async () => {
  const [bootstrap, nginx] = await Promise.all([readFile(bootstrapFile, 'utf8'), readFile(nginxFile, 'utf8')]);
  const match = bootstrap.match(/"event_url_base":\s*"([^"]+)"/);
  assert.ok(match, 'bootstrap must generate an explicit Artifact descriptor base');
  const descriptor = new URL('/api/v1/artifact-downloads/artifact-acceptance?signature=redacted', match[1]);
  assert.equal(descriptor.protocol, 'https:');
  assert.equal(descriptor.hostname, 'frontend');
  assert.equal(descriptor.port, '8443');
  assert.equal(descriptor.pathname, '/api/v1/artifact-downloads/artifact-acceptance');

  const frontend = loadCompose().services.frontend;
  assert.deepEqual(Object.keys(frontend.networks), ['acceptance']);
  assert.equal(frontend.user, '10001:10001');
  assert.equal(mountAt(frontend, '/acceptance/config').read_only, true);
  assert.equal(mountAt(frontend, '/acceptance/secrets').read_only, true);
  assert.equal(frontend.ports[0].target, Number(descriptor.port));
  assert.match(nginx, new RegExp(`listen\\s+${descriptor.port}`));
  assert.match(nginx, /location\s+\/api\//);
  assert.match(nginx, /proxy_pass\s+https:\/\/controlplane:8443/);
});

test('runner exports the complete exact Task 3 environment interface over read-only fixture mounts', () => {
  const runner = loadCompose().services['acceptance-runner'];
  assert.deepEqual(runner.environment, {
    EXPECTED_OFFLINE_AGENT_ID: 'agent-offline',
    EXPECTED_ONLINE_AGENT_ID: 'agent-online',
    FRONTEND_URL: 'https://frontend:8443',
    OIDC_CA_FILE: '/acceptance/config/ca.pem',
    OIDC_CREDENTIAL_FILE: '/acceptance/secrets/oidc-token-credential',
    OIDC_URL: 'https://oidc:9444',
    PROJECT_ID: 'project-acceptance',
    TENANT_ID: 'tenant-acceptance',
  });
  assert.equal(mountAt(runner, '/acceptance/config').read_only, true);
  assert.equal(mountAt(runner, '/acceptance/secrets').read_only, true);
});

test('runner image pins Playwright 1.62.0 and stages only the dedicated Task 3 inputs', async () => {
  const dockerfile = await readFile(runnerFile, 'utf8');
  assert.match(dockerfile, /^FROM mcr\.microsoft\.com\/playwright:v1\.62\.0-noble$/m);
  assert.match(dockerfile, /COPY .*backend\/test\/e2e\/full-stack\/package\.json .*backend\/test\/e2e\/full-stack\/package-lock\.json/);
  assert.match(dockerfile, /RUN npm ci --ignore-scripts/);
  assert.match(dockerfile, /COPY .*playwright\.config\.mjs .*acceptance\.spec\.mjs .*support\.mjs/);
  assert.doesNotMatch(dockerfile, /COPY\s+\.\s/);
  assert.match(dockerfile, /^USER pwuser$/m);
});

test('runner package contract rejects every unapproved root dependency group', () => {
  const validPackage = { devDependencies: { '@playwright/test': '1.62.0' } };
  const validLock = { packages: {
    '': { devDependencies: { '@playwright/test': '1.62.0' } },
    'node_modules/@playwright/test': { version: '1.62.0' },
  } };
  assert.doesNotThrow(() => assertExactRunnerPackageContract(validPackage, validLock, '1.62.0'));
  for (const group of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const packageWithExtra = structuredClone(validPackage);
    packageWithExtra[group] = { ...(packageWithExtra[group] ?? {}), 'unexpected-runtime': '9.9.9' };
    assert.throws(() => assertExactRunnerPackageContract(packageWithExtra, validLock, '1.62.0'), undefined, `package ${group}`);

    const lockWithExtra = structuredClone(validLock);
    lockWithExtra.packages[''][group] = { ...(lockWithExtra.packages[''][group] ?? {}), 'unexpected-runtime': '9.9.9' };
    assert.throws(() => assertExactRunnerPackageContract(validPackage, lockWithExtra, '1.62.0'), undefined, `lock ${group}`);
  }
});

test('runner package and lock resolve exactly @playwright/test 1.62.0 when Task 3 assets exist', {
  skip: !existsSync(runnerPackageFile) && !existsSync(runnerLockFile),
}, async () => {
  const [packageBody, lockBody, dockerfile] = await Promise.all([
    readFile(runnerPackageFile, 'utf8'),
    readFile(runnerLockFile, 'utf8'),
    readFile(runnerFile, 'utf8'),
  ]);
  const packageMetadata = JSON.parse(packageBody);
  const lock = JSON.parse(lockBody);
  const imageVersion = dockerfile.match(/^FROM mcr\.microsoft\.com\/playwright:v([0-9.]+)-noble$/m)?.[1];
  assertExactRunnerPackageContract(packageMetadata, lock, imageVersion);
});
