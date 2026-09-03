import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { spawn, spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const composeFile = join(repoRoot, 'backend', 'docker', 'host-plugin-full-stack', 'docker-compose.yml');
const nginxFile = join(repoRoot, 'backend', 'docker', 'host-plugin-full-stack', 'nginx.conf');
const runnerFile = join(repoRoot, 'backend', 'docker', 'host-plugin-full-stack', 'runner.Dockerfile');
const verifierFile = join(repoRoot, 'backend', 'scripts', 'verify-host-plugin-full-stack.ps1');
const boundedProcessFile = join(repoRoot, 'backend', 'scripts', 'bounded-process.ps1');
const boundedGateFile = join(repoRoot, 'backend', 'scripts', 'bounded-process-gate.ps1');
const containerSafetyFile = join(repoRoot, 'backend', 'scripts', 'container-safety.ps1');
const e2eRoot = join(repoRoot, 'backend', 'test', 'e2e', 'host-plugin-full-stack');
const approvedKylinImage = 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1';

const serviceNames = [
  'acceptance-runner',
  'agent',
  'assertion-exporter',
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
  'acceptance-assertion-input',
  'acceptance-assertion-secrets',
  'acceptance-bin',
  'acceptance-config',
  'acceptance-controlplane-secrets',
  'acceptance-enrollment-inbox',
  'acceptance-frontend-assets',
  'acceptance-frontend-tls',
  'acceptance-helper-runtime',
  'acceptance-mysql-primary-data',
  'acceptance-mysql-secondary-data',
  'acceptance-mysql-secrets',
  'acceptance-oidc-secrets',
  'acceptance-plugin-runtime',
  'acceptance-postgres-data',
  'acceptance-postgres-secrets',
  'acceptance-proc-runtime',
  'acceptance-runner-artifacts',
  'acceptance-runner-secrets',
  'acceptance-runner-trust',
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
      DBPILOT_HOST_PLUGIN_RUNNER_IMAGE: 'dbpilot-host-plugin-runner:contract000000000000000000000000',
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
    'assertion-exporter': approvedKylinImage,
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
  assert.equal(config.services['acceptance-runner'].image, 'dbpilot-host-plugin-runner:contract000000000000000000000000');
  assert.equal(config.services['acceptance-runner'].build.labels['dbpilot.verifier'], 'host-plugin-full-stack');
  assert.equal(config.services['acceptance-runner'].build.labels['dbpilot.run'], 'contract000000000000000000000000');

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
  assert.match(agentCommand, /if test ! -s \/acceptance\/agent-data\/enrollment\/agent\.crt; then\s+test -s \/acceptance\/enrollment-inbox\/enrollment-token/);
  assert.match(agentCommand, /controlled acceptance file-log source/);
  assert.match(agentCommand, /\/acceptance\/agent-data\/native\/mysqld-dbp/);
  assert.doesNotMatch(agentCommand, /\/tmp\/mysqld-dbp/);
});

test('runtime services receive only least-privilege secret and trust volumes', () => {
  const services = loadCompose().services;
  const secretSources = {
    postgres: 'acceptance-postgres-secrets',
    oidc: 'acceptance-oidc-secrets',
    controlplane: 'acceptance-controlplane-secrets',
    'mysql-primary': 'acceptance-mysql-secrets',
    'mysql-secondary': 'acceptance-mysql-secrets',
    frontend: 'acceptance-frontend-tls',
    'acceptance-runner': 'acceptance-runner-secrets',
    assertions: 'acceptance-assertion-secrets',
  };
  for (const [name, source] of Object.entries(secretSources)) {
    const mount = mountAt(services[name], '/acceptance/secrets');
    assert.ok(mount, `${name} receives its dedicated secret volume`);
    assert.equal(mount.source, source);
    assert.equal(mount.read_only, true);
  }
  for (const name of ['agent', 'docker-discovery', 'mysql-plugin', 'proc-helper']) {
    assert.equal(mountAt(services[name], '/acceptance/secrets'), undefined, `${name} cannot read bootstrap secrets`);
  }
  assert.equal(mountAt(services.frontend, '/acceptance/config').source, 'acceptance-frontend-tls');
  assert.equal(mountAt(services.frontend, '/etc/ssl/certs').source, 'acceptance-frontend-tls');
  assert.equal(mountAt(services['acceptance-runner'], '/acceptance/config').source, 'acceptance-runner-trust');
  const agentCommand = commandText(services.agent);
  const tokenRemoval = agentCommand.indexOf('rm -f /acceptance/enrollment-inbox/enrollment-token');
  assert.ok(tokenRemoval > agentCommand.indexOf('--output-dir /acceptance/agent-data/enrollment'));
  assert.ok(tokenRemoval < agentCommand.indexOf('exec /acceptance/bin/dbpilot-agent --config'),
    'the one-time enrollment token is removed before the long-running Agent starts');
  assert.deepEqual(writableTargets(services['asset-builder']), ['/acceptance/bin', '/acceptance/frontend']);
  assert.deepEqual(writableTargets(services.bootstrap), ['/volumes/agent-data', '/volumes/artifacts', '/volumes/assertion-input', '/volumes/assertion-secrets', '/volumes/config', '/volumes/controlplane-secrets', '/volumes/enrollment-inbox', '/volumes/frontend-tls', '/volumes/helper-runtime', '/volumes/mysql-secrets', '/volumes/oidc-secrets', '/volumes/plugin-runtime', '/volumes/postgres-secrets', '/volumes/proc-runtime', '/volumes/runner-artifacts', '/volumes/runner-secrets', '/volumes/runner-trust', '/volumes/state']);
  assert.deepEqual(writableTargets(services.postgres), ['/var/lib/postgresql/data']);
  assert.deepEqual(writableTargets(services.oidc), []);
  assert.deepEqual(writableTargets(services.controlplane), ['/acceptance/state']);
  assert.deepEqual(writableTargets(services.agent), ['/acceptance/agent-data', '/acceptance/agent-data/plugin-runtime', '/acceptance/enrollment-inbox', '/run/dbpilot-agent']);
  assert.equal(mountAt(services.agent, '/acceptance/agent-data').volume?.nocopy, true,
    'the pre-owned empty Agent volume must not be copy-up reset to root before enrollment');
  assert.deepEqual(writableTargets(services['proc-helper']), ['/run/dbpilot-agent']);
  assert.deepEqual(writableTargets(services['docker-discovery']), ['/acceptance/helper-runtime']);
  assert.deepEqual(writableTargets(services['mysql-primary']), ['/var/lib/mysql']);
  assert.deepEqual(writableTargets(services['mysql-secondary']), ['/var/lib/mysql']);
  assert.deepEqual(writableTargets(services['mysql-plugin']), []);
  assert.deepEqual(writableTargets(services.frontend), []);
  assert.deepEqual(writableTargets(services['acceptance-runner']), ['/acceptance/enrollment-inbox', '/acceptance/playwright', '/acceptance/state']);
  assert.equal(mountAt(services['acceptance-runner'], '/acceptance/agent-data'), undefined, 'ordinary browser phases cannot read Agent private state');
  assert.equal(mountAt(services.assertions, '/acceptance/agent-data'), undefined, 'assertions consume only the exported diagnostic projection');
  assert.equal(mountAt(services.assertions, '/acceptance/assertion-input').source, 'acceptance-assertion-input');
  assert.deepEqual(writableTargets(services['assertion-exporter']), ['/acceptance/assertion-input']);
  assert.equal(mountAt(services['assertion-exporter'], '/acceptance/agent-data').read_only, true);
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
  assert.match(commandText(loadCompose().services.bootstrap), /cp \/acceptance\/config\/ca\.pem \/volumes\/frontend-tls\/ca-certificates\.crt/);
});

test('Playwright runner is exactly locked and invokes only its package-owned suite', async () => {
  for (const name of ['package.json', 'package-lock.json', 'playwright.config.mjs', 'acceptance.spec.mjs']) {
    assert.equal(existsSync(join(e2eRoot, name)), true, `${name} exists`);
  }
  const metadata = JSON.parse(await readFile(join(e2eRoot, 'package.json'), 'utf8'));
  const lock = JSON.parse(await readFile(join(e2eRoot, 'package-lock.json'), 'utf8'));
  const playwrightConfig = await readFile(join(e2eRoot, 'playwright.config.mjs'), 'utf8');
  const acceptanceSpec = await readFile(join(e2eRoot, 'acceptance.spec.mjs'), 'utf8');
  const verifier = await readFile(verifierFile, 'utf8');
  const runner = await readFile(runnerFile, 'utf8');
  assert.deepEqual(metadata.devDependencies, { '@playwright/test': '1.62.0' });
  assert.equal(lock.packages['node_modules/@playwright/test'].version, '1.62.0');
  assert.equal(metadata.scripts.test, 'playwright test --config playwright.config.mjs');
  assert.match(runner, /plugin-package\.mjs/);
  assert.doesNotMatch(acceptanceSpec, /\bbuildPackage\(/);
  assert.match(playwrightConfig, /outputDir:\s*'\/acceptance\/playwright\/results'/);
  assert.match(acceptanceSpec, /data:\s*options\.body\s*\?\?\s*options\.data/);
  assert.match(acceptanceSpec, /PLUGIN_ARM64_BINARY_FILE/);
  assert.match(acceptanceSpec, /plugin_signature_rejected/);
  assert.match(acceptanceSpec, /plugin_platform_mismatch/);
  assert.match(acceptanceSpec, /high_cardinality/);
  assert.match(acceptanceSpec, /first_instance_pid/);
  for (const boundary of ['capture-agent-restart', 'capture-agent-stopped', 'convergence-agent', 'capture-server-restart', 'capture-server-stopped', 'convergence-server']) {
    assert.ok(acceptanceSpec.includes(boundary), `restart evidence contains ${boundary}`);
  }
  assert.match(acceptanceSpec, /RESTART_BOUNDARY_UTC/);
  assert.match(verifier, /capture-agent-stopped[\s\S]*RESTART_BOUNDARY_UTC/);
  assert.match(verifier, /capture-server-stopped[\s\S]*RESTART_BOUNDARY_UTC/);
  assert.match(acceptanceSpec, /observed_at[\s\S]*sample_at/);
  assert.match(acceptanceSpec, /page\.on\('request'/);
  assert.match(acceptanceSpec, /rotatedToken/);
  assert.match(acceptanceSpec, /page\.exposeFunction\('__DBPilotAcceptanceReadToken'/);
  assert.doesNotMatch(acceptanceSpec, /__DBPilotAcceptanceCurrentToken/);
  assert.doesNotMatch(acceptanceSpec, /route\.continue\(\{\s*headers/);
  assert.match(acceptanceSpec, /failure-canary/);
  assert.match(acceptanceSpec, /diagnostic_stage/);
  assert.match(verifier, /Get-AcceptanceFailureStage/);
  assert.match(verifier, /Assert-FailureCanariesAbsent/);
  const canaryScanner = verifier.slice(verifier.indexOf('function Assert-FailureCanariesAbsent'), verifier.indexOf('function Remove-SafeFailureArtifactDirectory'));
  assert.doesNotMatch(canaryScanner, /--tail/);
  assert.doesNotMatch(canaryScanner, /ExitCode\s+-ne\s+0\)\s*\{\s*continue/);
  assert.match(canaryScanner, /StdoutTruncated[\s\S]*throw/);
  assert.match(canaryScanner, /StderrTruncated[\s\S]*throw/);
  assert.doesNotMatch(verifier, /\.png/);
  assert.doesNotMatch(verifier, /playwright\/\./);
  assert.match(await readFile(join(repoRoot, 'backend', 'test', 'fixtures', 'fullstack', 'host_plugin_assertions.go'), 'utf8'), /candidate_metrics='\[\]'::jsonb/);
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
  assert.match(verifier, /ownedImageIDs/);
  assert.match(verifier, /DBPILOT_HOST_PLUGIN_RUNNER_IMAGE/);
  assert.match(verifier, /runnerImageReference/);
  assert.match(verifier, /Remove-OwnedRunnerImage/);
  assert.match(verifier, /image', 'ls'[\s\S]*label=dbpilot\.verifier/);
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

test('runner image build and registration failure windows remain exact-cleanable', async () => {
  const verifier = await readFile(verifierFile, 'utf8');
  const resources = verifier.slice(verifier.indexOf('function Register-OwnedResources'), verifier.indexOf('function Register-OwnedRunnerImageID'));
  const discovery = verifier.slice(verifier.indexOf('function Register-OwnedRunnerImages'), verifier.indexOf('function Remove-OwnedRunnerImage'));
  const finalizer = verifier.slice(verifier.lastIndexOf('finally {'));
  const imageReference = verifier.indexOf('$runnerImageReference = "dbpilot-host-plugin-runner:$RunId"');
  const imageBuild = verifier.indexOf("@('build', 'acceptance-runner')");
  assert.ok(imageReference >= 0 && imageReference < imageBuild, 'the unique image identity is declared before the risky build');
  assert.match(resources, /Register-OwnedRunnerImages -RetrySeconds \$RunnerImageRetrySeconds/);
  assert.match(discovery, /image', 'inspect'[\s\S]*\$runnerImageReference/);
  assert.match(discovery, /label=dbpilot\.verifier=\$verifierLabel[\s\S]*label=dbpilot\.run=\$RunId/);
  assert.match(discovery, /Register-OwnedRunnerImageID \$candidate/);
  assert.match(discovery, /Start-Sleep -Seconds 1/);
  assert.match(finalizer, /Register-OwnedResources -RunnerImageRetrySeconds 5[\s\S]*Remove-OwnedRunnerImage \$id/,
    'finally retries late image visibility, records the canonical ID, then removes only that ID');
});

test('PowerShell 5.1 and 7 atomically own a zero-delay parent and pipe-holding child', { skip: process.platform !== 'win32' }, async () => {
  assert.equal(existsSync(boundedProcessFile), true, 'the production bounded-process helper exists');
  assert.equal(existsSync(boundedGateFile), true, 'the pre-assignment process gate exists');
  const boundedSource = await readFile(boundedProcessFile, 'utf8');
  const gateSource = await readFile(boundedGateFile, 'utf8');
  assert.match(boundedSource, /CreateKillOnClose\(\)[\s\S]*\$process\.Start\(\)[\s\S]*Assign\([^\r\n]+\)[\s\S]*\.Set\(\)/);
  assert.match(gateSource, /WaitOne\([^)]*\)[\s\S]*& \$command @arguments/);
  const root = await mkdtemp(join(tmpdir(), 'dbpilot-pipe-'));
  const child = join(root, 'child.ps1');
  const parentSource = join(root, 'parent.cs');
  const parent = join(root, 'parent.exe');
  const pidFile = join(root, 'child.pid');
  await writeFile(child, "[Console]::Out.WriteLine('pipe-held'); Start-Sleep -Seconds 30\n", 'utf8');
  await writeFile(parentSource, [
    'using System;',
    'using System.Diagnostics;',
    'using System.IO;',
    'public static class ImmediateParent {',
    '  public static int Main() {',
    '    var info = new ProcessStartInfo(Environment.GetEnvironmentVariable("DBPILOT_PIPE_CHILD_EXE"), "-NoProfile -File \\\"" + Environment.GetEnvironmentVariable("DBPILOT_PIPE_CHILD") + "\\\"");',
    '    info.UseShellExecute = false; info.CreateNoWindow = true;',
    '    var child = Process.Start(info);',
    '    File.WriteAllText(Environment.GetEnvironmentVariable("DBPILOT_PIPE_PID"), child.Id.ToString());',
    '    return 0;',
    '  }',
    '}',
    '',
  ].join('\n'), 'utf8');
  const compiler = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const compile = spawnSync(compiler, ['-NoProfile', '-Command', `Add-Type -TypeDefinition ([IO.File]::ReadAllText($env:DBPILOT_PARENT_SOURCE)) -OutputAssembly $env:DBPILOT_PIPE_PARENT -OutputType ConsoleApplication`], { encoding: 'utf8', env: { ...process.env, DBPILOT_PARENT_SOURCE: parentSource, DBPILOT_PIPE_PARENT: parent } });
  assert.equal(compile.status, 0, compile.stderr || compile.stdout);
  try {
    for (const executable of [
      'pwsh',
      join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    ]) {
      if (executable !== 'pwsh' && !existsSync(executable)) continue;
      const unrelated = spawn(executable, ['-NoProfile', '-Command', 'Start-Sleep -Seconds 30'], { stdio: 'ignore' });
      const command = [
        `. '${containerSafetyFile.replaceAll("'", "''")}'`,
        `. '${boundedProcessFile.replaceAll("'", "''")}'`,
        "try { Invoke-BoundedProcess -Command $env:DBPILOT_PIPE_PARENT -Arguments @() -TimeoutSeconds 2 -StartFailure 'pipe start' -TimeoutFailure 'pipe deadline'; exit 9 } catch { if ($_.Exception.Message -cne 'pipe deadline') { Write-Error $_; exit 8 } }; exit 0",
      ].join('; ');
      const started = Date.now();
      try {
        const result = spawnSync(executable, ['-NoProfile', '-Command', command], {
          cwd: repoRoot,
          encoding: 'utf8',
          timeout: 12_000,
          env: { ...process.env, DBPILOT_PIPE_CHILD_EXE: executable, DBPILOT_PIPE_CHILD: child, DBPILOT_PIPE_PARENT: parent, DBPILOT_PIPE_PID: pidFile },
        });
        assert.equal(result.status, 0, `${executable} did not bound the inherited output pipe: ${result.stderr || result.stdout}`);
        assert.ok(Date.now() - started < 8_000, `${executable} exceeded the bounded output deadline`);
        const childPID = Number((await readFile(pidFile, 'utf8')).trim());
        const alive = spawnSync(executable, ['-NoProfile', '-Command', `if (Get-Process -Id ${childPID} -ErrorAction SilentlyContinue) { exit 1 }`]);
        assert.equal(alive.status, 0, `${executable} left the exact pipe-holding child alive`);
        const unrelatedAlive = spawnSync(executable, ['-NoProfile', '-Command', `if (-not (Get-Process -Id ${unrelated.pid} -ErrorAction SilentlyContinue)) { exit 1 }`]);
        assert.equal(unrelatedAlive.status, 0, `${executable} terminated an unrelated process`);
        await rm(pidFile, { force: true });
      } finally {
        unrelated.kill();
      }
    }
  } finally {
    await rm(root, { recursive: true, force: true });
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
