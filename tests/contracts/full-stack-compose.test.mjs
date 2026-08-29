import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const composeFile = join(repoRoot, 'backend', 'docker', 'full-stack', 'docker-compose.yml');
const nginxFile = join(repoRoot, 'backend', 'docker', 'full-stack', 'nginx.conf');
const runnerFile = join(repoRoot, 'backend', 'docker', 'full-stack', 'runner.Dockerfile');

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

test('Compose resolves the exact isolated full-stack service, image, network, and volume topology', () => {
  const config = loadCompose();
  assert.deepEqual(Object.keys(config.services).sort(), serviceNames);
  assert.deepEqual(Object.keys(config.volumes).sort(), volumeNames);
  assert.deepEqual(Object.keys(config.networks), ['acceptance']);
  assert.equal(config.networks.acceptance.internal, true);
  assert.equal(config.networks.acceptance.driver, 'bridge');

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
    assert.deepEqual(Object.keys(service.networks), ['acceptance'], `${name} must use only the acceptance network`);
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

test('only frontend publishes a Docker-assigned loopback port and dependencies use completion or health conditions', () => {
  const config = loadCompose();
  for (const [name, service] of Object.entries(config.services)) {
    if (name === 'frontend') {
      assert.equal(service.ports.length, 1);
      assert.equal(service.ports[0].host_ip, '127.0.0.1');
      assert.equal(service.ports[0].target, 8080);
      assert.equal(service.ports[0].published, '0');
    } else {
      assert.equal(service.ports, undefined, `${name} must not publish a host port`);
    }
  }
  assert.ok(config.services.postgres.healthcheck);
  assert.ok(config.services.oidc.healthcheck);
  assert.ok(config.services.controlplane.healthcheck);
  assert.ok(config.services.frontend.healthcheck);
  assert.equal(config.services.bootstrap.depends_on['asset-builder'].condition, 'service_completed_successfully');
  assert.equal(config.services.postgres.depends_on.bootstrap.condition, 'service_completed_successfully');
  assert.equal(config.services.oidc.depends_on.bootstrap.condition, 'service_completed_successfully');
  assert.equal(config.services.controlplane.depends_on.postgres.condition, 'service_healthy');
  assert.equal(config.services.controlplane.depends_on.oidc.condition, 'service_healthy');
  assert.equal(config.services.agent.depends_on.controlplane.condition, 'service_healthy');
  assert.equal(config.services.frontend.depends_on.controlplane.condition, 'service_healthy');
  assert.equal(config.services['acceptance-runner'].depends_on.frontend.condition, 'service_healthy');
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
  assert.match(nginx, /listen\s+8080/);
  assert.match(nginx, /location\s*=\s*\/healthz/);
  assert.match(nginx, /root\s+\/srv\/dbpilot\/frontend/);
  assert.match(nginx, /location\s+\/api\//);
  assert.match(nginx, /proxy_pass\s+https:\/\/controlplane:8443/);
  assert.match(nginx, /proxy_ssl_verify\s+on/);
  assert.match(nginx, /proxy_ssl_server_name\s+on/);
  assert.match(nginx, /proxy_ssl_name\s+controlplane/);
  assert.match(nginx, /proxy_ssl_trusted_certificate\s+\/acceptance\/config\/ca\.pem/);
  assert.match(nginx, /proxy_buffering\s+off/);
  assert.match(nginx, /client_max_body_size\s+\d+[km]/i);
  assert.match(nginx, /proxy_(?:connect|read|send)_timeout\s+\d+s/);
  assert.doesNotMatch(nginx, /oidc|\/token|acceptance\/secrets/i);
});

test('runner image pins Playwright 1.62.0, installs only its locked package, and drops to pwuser', async () => {
  const dockerfile = await readFile(runnerFile, 'utf8');
  assert.match(dockerfile, /^FROM mcr\.microsoft\.com\/playwright:v1\.62\.0-noble$/m);
  assert.match(dockerfile, /COPY .*backend\/test\/e2e\/full-stack\/package\.json .*backend\/test\/e2e\/full-stack\/package-lock\.json/);
  assert.match(dockerfile, /RUN npm ci --ignore-scripts/);
  assert.match(dockerfile, /COPY .*playwright\.config\.mjs .*acceptance\.spec\.mjs/);
  assert.doesNotMatch(dockerfile, /COPY\s+\.\s/);
  assert.match(dockerfile, /^USER pwuser$/m);
});
