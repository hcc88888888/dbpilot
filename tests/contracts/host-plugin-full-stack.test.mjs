import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const composeFile = join(repoRoot, 'backend', 'docker', 'host-plugin-full-stack', 'docker-compose.yml');
const nginxFile = join(repoRoot, 'backend', 'docker', 'host-plugin-full-stack', 'nginx.conf');
const runnerFile = join(repoRoot, 'backend', 'docker', 'host-plugin-full-stack', 'runner.Dockerfile');
const verifierFile = join(repoRoot, 'backend', 'scripts', 'verify-host-plugin-full-stack.ps1');
const e2eRoot = join(repoRoot, 'backend', 'test', 'e2e', 'host-plugin-full-stack');
const approvedKylinImage = 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1';

const serviceNames = [
  'acceptance-runner',
  'agent',
  'assertions',
  'asset-builder',
  'bootstrap',
  'controlplane',
  'docker-discovery',
  'frontend',
  'mysql-plugin',
  'mysql-primary',
  'mysql-secondary',
  'oidc',
  'postgres',
  'proc-helper',
];

const volumeNames = [
  'acceptance-agent-data',
  'acceptance-artifacts',
  'acceptance-bin',
  'acceptance-config',
  'acceptance-frontend-assets',
  'acceptance-helper-runtime',
  'acceptance-mysql-primary-data',
  'acceptance-mysql-secondary-data',
  'acceptance-plugin-runtime',
  'acceptance-postgres-data',
  'acceptance-proc-runtime',
  'acceptance-runner-artifacts',
  'acceptance-secrets',
  'acceptance-state',
];

function loadCompose() {
  assert.equal(existsSync(composeFile), true, 'host plugin full-stack Compose topology exists');
  const result = spawnSync('docker', ['compose', '-f', composeFile, '--profile', '*', 'config', '--format', 'json'], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      DBPILOT_HOST_PLUGIN_RUN_ID: 'contract000000000000000000000000',
      DBPILOT_KYLIN_IMAGE: approvedKylinImage,
    },
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout);
}

function mountAt(service, target) {
  return (service.volumes ?? []).find((mount) => mount.target === target);
}

function writableTargets(service) {
  return (service.volumes ?? [])
    .filter((mount) => mount.type === 'volume' && mount.read_only !== true)
    .map((mount) => mount.target)
    .sort();
}

function commandText(service) {
  return [...(service.entrypoint ?? []), ...(service.command ?? [])].join(' ');
}

test('host plugin Compose resolves the exact labelled production topology', () => {
  const config = loadCompose();
  assert.deepEqual(Object.keys(config.services).sort(), serviceNames);
  assert.deepEqual(Object.keys(config.networks).sort(), ['acceptance', 'builder-egress', 'frontend-edge', 'proc-isolation']);
  assert.deepEqual(Object.keys(config.volumes).sort(), volumeNames);
  assert.equal(config.networks.acceptance.internal, true);
  assert.equal(config.networks['proc-isolation'].internal, true);
  assert.notEqual(config.networks['builder-egress'].internal, true);
  assert.notEqual(config.networks['frontend-edge'].internal, true);

  const exactImages = {
    'asset-builder': 'golang:1.27.0-bookworm',
    bootstrap: approvedKylinImage,
    postgres: 'postgres:16-alpine',
    oidc: approvedKylinImage,
    controlplane: approvedKylinImage,
    agent: approvedKylinImage,
    'proc-helper': approvedKylinImage,
    'docker-discovery': approvedKylinImage,
    'mysql-primary': 'mysql:8.4',
    'mysql-secondary': 'mysql:8.4',
    'mysql-plugin': approvedKylinImage,
    frontend: 'nginx:1.29.1-alpine',
    assertions: approvedKylinImage,
  };
  for (const [name, image] of Object.entries(exactImages)) {
    assert.equal(config.services[name].image, image, `${name} uses its approved image`);
    if (image === approvedKylinImage) {
      assert.equal(config.services[name].platform, 'linux/amd64', `${name} selects the Kylin amd64 manifest`);
    }
  }
  assert.equal(config.services['acceptance-runner'].build.dockerfile, 'backend/docker/host-plugin-full-stack/runner.Dockerfile');

  for (const [name, service] of Object.entries(config.services)) {
    assert.equal(service.labels['dbpilot.verifier'], 'host-plugin-full-stack', `${name} has verifier ownership`);
    assert.equal(service.labels['dbpilot.run'], 'contract000000000000000000000000', `${name} has run ownership`);
    assert.equal(service.restart, 'no', `${name} is verifier-owned rather than daemon-owned`);
    assert.ok(service.cpus, `${name} has a CPU bound`);
    assert.ok(service.mem_limit, `${name} has a memory bound`);
    assert.ok(service.pids_limit, `${name} has a PID bound`);
  }
  for (const resource of [...Object.values(config.networks), ...Object.values(config.volumes)]) {
    assert.equal(resource.labels['dbpilot.verifier'], 'host-plugin-full-stack');
    assert.equal(resource.labels['dbpilot.run'], 'contract000000000000000000000000');
  }
});

test('only the frontend publishes an ephemeral loopback port', () => {
  const services = loadCompose().services;
  for (const [name, service] of Object.entries(services)) {
    if (name !== 'frontend') assert.deepEqual(service.ports ?? [], [], `${name} must remain acceptance-network only`);
  }
  assert.equal(services.frontend.ports.length, 1);
  assert.equal(services.frontend.ports[0].host_ip, '127.0.0.1');
  assert.equal(Number(services.frontend.ports[0].published), 0);
  assert.equal(Number(services.frontend.ports[0].target), 8443);
});

test('only the restricted Docker discovery helper owns the raw Docker Socket boundary', () => {
  const services = loadCompose().services;
  const holders = Object.entries(services).filter(([, service]) => mountAt(service, '/var/run/docker.sock'));
  assert.deepEqual(holders.map(([name]) => name), ['docker-discovery']);
  const socket = mountAt(services['docker-discovery'], '/var/run/docker.sock');
  assert.equal(socket.type, 'bind');
  assert.equal(socket.read_only, true);
  assert.equal(services['docker-discovery'].user, '0:10001', 'helper owns the Docker Socket while its AF_UNIX socket is born in the Agent group');
  assert.equal(services['docker-discovery'].read_only, true);
  assert.deepEqual(services['docker-discovery'].cap_drop, ['ALL']);
  assert.ok(services['docker-discovery'].security_opt.includes('no-new-privileges:true'));
  assert.match(commandText(services['docker-discovery']), /--allowed-uid 10001 --allowed-gid 10001/);
  assert.match(commandText(services['docker-discovery']), /--allowed-networks/);
  assert.match(commandText(services.bootstrap), /chown 0:10001 \/volumes\/helper-runtime/);
  assert.match(commandText(services.bootstrap), /chmod 0770 \/volumes\/helper-runtime/);
  assert.doesNotMatch(commandText(services['docker-discovery']), /\b(?:POST|PUT|PATCH|DELETE|attach|archive)\b/i);
});

test('native discovery crosses only the bounded process helper', () => {
  const services = loadCompose().services;
  const helper = services['proc-helper'];
  assert.equal(helper.user, '0:10001', 'container proof uses the documented CentOS-compatible exact-capability helper profile');
  assert.equal(helper.pid, 'service:agent');
  assert.deepEqual(Object.keys(helper.networks), ['proc-isolation']);
  assert.deepEqual(helper.cap_drop, ['ALL']);
  assert.deepEqual(helper.cap_add, ['DAC_READ_SEARCH', 'SYS_PTRACE']);
  assert.ok(helper.security_opt.includes('no-new-privileges:true'));
  assert.ok(helper.security_opt.includes('apparmor=unconfined'), 'cross-container PID evidence disables Docker default AppArmor while retaining only documented proc-read capabilities, one isolated internal network, and no secret mounts');
  assert.match(commandText(helper), /dbpilot-agent proc-helper/);
  assert.match(commandText(helper), /--allowed-uid 10001 --allowed-gid 10001/);
  assert.match(commandText(helper), /--allowed-process-names mysqld-dbp/);
  assert.equal(mountAt(services.agent, '/run/dbpilot-agent').source, 'acceptance-proc-runtime');
  assert.equal(mountAt(helper, '/run/dbpilot-agent').source, 'acceptance-proc-runtime');
  for (const target of ['/acceptance/config', '/acceptance/secrets', '/acceptance/artifacts', '/var/run/docker.sock']) {
    assert.equal(mountAt(helper, target), undefined, `native helper cannot read ${target}`);
  }
});

test('one MySQL plugin process is configured for both MySQL instances', () => {
  const services = loadCompose().services;
  assert.equal(Object.keys(services).filter((name) => name === 'mysql-plugin').length, 1);
  assert.deepEqual(services['mysql-plugin'].depends_on, {
    agent: { condition: 'service_started', required: true },
    'mysql-primary': { condition: 'service_healthy', required: true },
    'mysql-secondary': { condition: 'service_healthy', required: true },
  });
  const command = commandText(services['mysql-plugin']);
  assert.match(command, /dbpilot-plugin-mysql/);
  assert.match(command, /pgrep -fc '\/dbpilot-plugin-mysql '/);
  assert.match(command, /test "\$\$\{count\}" -eq 1/);
  assert.equal((command.match(/pgrep -fc '\/dbpilot-plugin-mysql '/g) ?? []).length, 1);
  assert.doesNotMatch(command, /\/acceptance\/bin\/dbpilot-plugin-mysql/);
  const agentCommand = commandText(services.agent);
  assert.match(agentCommand, /controlled acceptance file-log source/);
  assert.match(agentCommand, /\/acceptance\/agent-data\/native\/mysqld-dbp/);
  assert.doesNotMatch(agentCommand, /\/tmp\/mysqld-dbp/);
});

test('runtime services consume artifacts configuration and secrets read-only with exact writable volumes', () => {
  const services = loadCompose().services;
  for (const name of ['controlplane', 'agent', 'docker-discovery', 'mysql-plugin', 'frontend', 'acceptance-runner', 'assertions']) {
    for (const target of ['/acceptance/artifacts', '/acceptance/config', '/acceptance/secrets']) {
      const mount = mountAt(services[name], target);
      assert.ok(mount, `${name} mounts ${target}`);
      assert.equal(mount.read_only, true, `${name} cannot mutate ${target}`);
    }
  }
  assert.deepEqual(writableTargets(services['asset-builder']), ['/acceptance/bin', '/acceptance/frontend']);
  assert.deepEqual(writableTargets(services.bootstrap), ['/volumes/agent-data', '/volumes/artifacts', '/volumes/config', '/volumes/helper-runtime', '/volumes/plugin-runtime', '/volumes/proc-runtime', '/volumes/runner-artifacts', '/volumes/secrets', '/volumes/state']);
  assert.deepEqual(writableTargets(services.postgres), ['/var/lib/postgresql/data']);
  assert.deepEqual(writableTargets(services.oidc), []);
  assert.deepEqual(writableTargets(services.controlplane), ['/acceptance/state']);
  assert.deepEqual(writableTargets(services.agent), ['/acceptance/agent-data', '/acceptance/agent-data/plugin-runtime', '/run/dbpilot-agent']);
  assert.deepEqual(writableTargets(services['proc-helper']), ['/run/dbpilot-agent']);
  assert.deepEqual(writableTargets(services['docker-discovery']), ['/acceptance/helper-runtime']);
  assert.deepEqual(writableTargets(services['mysql-primary']), ['/var/lib/mysql']);
  assert.deepEqual(writableTargets(services['mysql-secondary']), ['/var/lib/mysql']);
  assert.deepEqual(writableTargets(services['mysql-plugin']), []);
  assert.deepEqual(writableTargets(services.frontend), []);
  assert.deepEqual(writableTargets(services['acceptance-runner']), ['/acceptance/agent-data', '/acceptance/playwright', '/acceptance/state']);
  assert.deepEqual(writableTargets(services.assertions), ['/acceptance/state']);
});

test('production frontend serves Vite assets through query-safe same-origin Nginx', async () => {
  for (const file of [nginxFile, runnerFile]) assert.equal(existsSync(file), true, `${file} exists`);
  const nginx = await readFile(nginxFile, 'utf8');
  assert.match(nginx, /listen\s+8443\s+ssl/);
  assert.match(nginx, /client_max_body_size\s+256m/);
  assert.match(nginx, /location\s+\/api\//);
  assert.match(nginx, /proxy_pass\s+https:\/\/controlplane:/);
  assert.match(nginx, /try_files\s+\$uri(?:\s+\$uri\/)?\s+\/index\.html/);
  assert.match(nginx, /log_format\s+query_safe/);
  assert.doesNotMatch(nginx, /\$(?:request_uri|args|query_string)/);
  assert.match(nginx, /access_log\s+\/dev\/stdout\s+query_safe/);
  const frontend = loadCompose().services.frontend;
  assert.equal(mountAt(frontend, '/etc/ssl/certs').read_only, true, 'frontend health probe trusts only generated acceptance CA bundle');
});

test('Playwright runner is exactly locked and invokes only its package-owned suite', async () => {
  for (const name of ['package.json', 'package-lock.json', 'playwright.config.mjs', 'acceptance.spec.mjs']) {
    assert.equal(existsSync(join(e2eRoot, name)), true, `${name} exists`);
  }
  const metadata = JSON.parse(await readFile(join(e2eRoot, 'package.json'), 'utf8'));
  const lock = JSON.parse(await readFile(join(e2eRoot, 'package-lock.json'), 'utf8'));
  const playwrightConfig = await readFile(join(e2eRoot, 'playwright.config.mjs'), 'utf8');
  const acceptanceSpec = await readFile(join(e2eRoot, 'acceptance.spec.mjs'), 'utf8');
  assert.deepEqual(metadata.devDependencies, { '@playwright/test': '1.62.0' });
  assert.equal(lock.packages['node_modules/@playwright/test'].version, '1.62.0');
  assert.equal(metadata.scripts.test, 'playwright test --config playwright.config.mjs');
  assert.match(playwrightConfig, /outputDir:\s*'\/acceptance\/playwright\/results'/);
  assert.match(acceptanceSpec, /data:\s*options\.body\s*\?\?\s*options\.data/);
});

test('PowerShell verifier has bounded ownership-safe lifecycle on Windows PowerShell and pwsh', async () => {
  assert.equal(existsSync(verifierFile), true, 'host plugin verifier exists');
  const verifier = await readFile(verifierFile, 'utf8');
  assert.match(verifier, /DBPILOT_HOST_PLUGIN_RUN_ID/);
  assert.match(verifier, /dbpilot\.verifier=host-plugin-full-stack/);
  assert.match(verifier, /Remove-DBPilotRecordedContainer/);
  assert.match(verifier, /Remove-DBPilotRecordedNetwork/);
  assert.match(verifier, /Remove-DBPilotRecordedVolume/);
  assert.match(verifier, /Assert-ZeroResidualResources/);
  assert.doesNotMatch(verifier, /Get-ComposeArguments @\('pull'/, 'release verification must use exact local image identities without registry drift');
  for (const image of ['golang:1.27.0-bookworm', 'postgres:16-alpine', 'nginx:1.29.1-alpine', 'mysql:8.4']) {
    assert.match(verifier, new RegExp(image.replace(/[.:]/g, '\\$&')));
  }
  for (const value of ["CGO_ENABLED', '0", "GOOS', 'linux", "GOARCH', 'amd64", './cmd/controlplane', './cmd/agent', './cmd/dbpilot-docker-discovery', './cmd/dbpilot-plugin-mysql']) {
    assert.ok(verifier.includes(value), `static build contract contains ${value}`);
  }
  assert.doesNotMatch(verifier, /\b(?:system|container|image|network|volume)\s+prune\b/i);
  assert.doesNotMatch(verifier, /compose[^\r\n]*(?:down|rm)[^\r\n]*(?:--volumes|-v)\b/i);
  assert.doesNotMatch(verifier, /docker[^\r\n]*(?:rm|stop)[^\r\n]*[?*]/i);

  for (const executable of [
    'pwsh',
    join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
  ]) {
    const result = spawnSync(executable, ['-NoProfile', '-Command',
      '$errors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($env:DBPILOT_PARSE_FILE,[ref]$null,[ref]$errors); if($errors.Count){$errors | ForEach-Object { Write-Error $_ }; exit 1}'],
    { cwd: repoRoot, encoding: 'utf8', env: { ...process.env, DBPILOT_PARSE_FILE: verifierFile } });
    assert.equal(result.status, 0, `${executable} parses verifier: ${result.stderr}`);
  }
});

test('repository Node gate is explicit and cannot recursively collect package-owned Playwright or Vitest suites', async () => {
  const metadata = JSON.parse(await readFile(join(repoRoot, 'package.json'), 'utf8'));
  const legacy = JSON.parse(await readFile(join(repoRoot, 'backend', 'test', 'e2e', 'full-stack', 'package.json'), 'utf8'));
  assert.equal(metadata.scripts['test:node'], 'node --test tests/contracts/*.test.mjs frontend/tests/*.test.js && npm --prefix backend/test/e2e/full-stack run test:support');
  assert.equal(legacy.scripts['test:support'], 'node --test support.test.mjs');
  assert.doesNotMatch(metadata.scripts['test:node'], /(?:^|\s)node\s+--test\s*$/);
  assert.doesNotMatch(metadata.scripts['test:node'], /frontend\/app|acceptance\.spec\.mjs|host-plugin-full-stack|node\s+--test\s+backend\/test\/e2e/);
});
