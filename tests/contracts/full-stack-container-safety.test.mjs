import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const verifier = join(repoRoot, 'backend', 'scripts', 'verify-full-stack-compose.ps1');
const workflow = join(repoRoot, '.github', 'workflows', 'contracts.yml');
const containerSafetyHelper = join(repoRoot, 'backend', 'scripts', 'container-safety.ps1');
const approvedImage = 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1';
const windowsPowerShellBinary = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');

function pwsh(args, env = {}) {
  return spawnSync('pwsh', ['-NoProfile', ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: { ...process.env, ...env },
    timeout: 120_000,
  });
}

function windowsPowerShell(args, env = {}) {
  return spawnSync(windowsPowerShellBinary, ['-NoProfile', ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: { ...process.env, ...env },
    timeout: 180_000,
  });
}

async function fakeRuntime(mode = 'success', { withSpaces = false } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'dbpilot-full-stack-fake-'));
  const runtimeRoot = withSpaces ? join(root, 'runtime with spaces') : root;
  if (withSpaces) await mkdir(runtimeRoot);
  const docker = join(runtimeRoot, 'docker fake.ps1');
  const go = join(runtimeRoot, 'go fake.ps1');
  const log = join(runtimeRoot, 'docker calls.log');
  const source = String.raw`
$line = $args -join ' '
[IO.File]::AppendAllText($env:DOCKER_LOG, $line + [Environment]::NewLine)
$history = [IO.File]::ReadAllText($env:DOCKER_LOG)
$containers = @('builder-id','bootstrap-id','postgres-id','oidc-id','controlplane-id','agent-id','frontend-id','runner-normal-id','runner-unauthorized-id','assertion-initial-id','runner-post-id','rogue-untrusted-id','runner-rogue-untrusted-id','rogue-mismatch-id','runner-rogue-mismatch-id','assertion-replay-id','assertion-journal-id','assertion-final-id','assertion-summary-id')
$volumes = @('volume-bin','volume-secrets','volume-config','volume-state','volume-artifacts','volume-agent','volume-runner','volume-go-cache','volume-rogue-untrusted','volume-rogue-mismatch')
$networks = @('network-acceptance','network-builder')
function Present([string]$kind, [string]$id) {
  if ($kind -eq 'container') { return $history -notmatch "(?m)^rm -f -v $([regex]::Escape($id))\r?$" }
  if ($kind -eq 'network') { return $history -notmatch "(?m)^network rm $([regex]::Escape($id))\r?$" }
  return $history -notmatch "(?m)^volume rm $([regex]::Escape($id))\r?$"
}
function CreatedContainer([string]$id) {
  switch ($id) {
    'builder-id' { return $history -match ' up --pull never -d --no-deps asset-builder' }
    'bootstrap-id' { return $history -match ' up --pull never -d --no-deps bootstrap' }
    'postgres-id' { return $history -match ' up --pull never -d --no-deps postgres oidc' }
    'oidc-id' { return $history -match ' up --pull never -d --no-deps postgres oidc' }
    'controlplane-id' { return $history -match ' up --pull never -d --no-deps controlplane' }
    'agent-id' { return $history -match ' up --pull never -d --no-deps agent' }
    'frontend-id' { return $history -match ' up --pull never -d --no-deps frontend' }
    'runner-normal-id' { return $history -match 'acceptance-runner normal' }
    'runner-unauthorized-id' { return $history -match 'acceptance-runner unauthorized' }
    'assertion-initial-id' { return ([regex]::Matches($history, 'DBPILOT_ASSERTION_PHASE=database.*assertions')).Count -ge 1 }
    'runner-post-id' { return $history -match 'acceptance-runner post-restart' }
    'rogue-untrusted-id' { return $history -match 'run -d --no-deps rogue-untrusted' }
    'runner-rogue-untrusted-id' { return $history -match 'ROGUE_KIND=untrusted.*acceptance-runner rogue' }
    'rogue-mismatch-id' { return $history -match 'run -d --no-deps rogue-mismatch' }
    'runner-rogue-mismatch-id' { return $history -match 'ROGUE_KIND=mismatch.*acceptance-runner rogue' }
    'assertion-replay-id' { return $history -match 'DBPILOT_ASSERTION_PHASE=replay.*assertions' }
    'assertion-journal-id' { return $history -match 'DBPILOT_ASSERTION_PHASE=journal.*assertions' }
    'assertion-final-id' { return ([regex]::Matches($history, 'DBPILOT_ASSERTION_PHASE=database.*assertions')).Count -ge 2 }
    'assertion-summary-id' { return $history -match 'DBPILOT_ASSERTION_PHASE=summary.*assertions' }
    default { return $false }
  }
}
function CreatedNetwork([string]$id) {
  if ($id -eq 'network-builder') { return $history -match ' up --pull never -d --no-deps asset-builder' }
  return $history -match ' up --pull never -d --no-deps bootstrap'
}
function CreatedVolume([string]$id) {
  if ($id -in @('volume-bin','volume-go-cache')) { return $history -match ' up --pull never -d --no-deps asset-builder' }
  return $history -match ' up --pull never -d --no-deps bootstrap'
}
if ($args[0] -eq 'version') { Write-Output '29.7.2'; $global:LASTEXITCODE=0; return }
if ($args[0] -eq 'info') { Write-Output 'amd64'; $global:LASTEXITCODE=0; return }
if ($args[0] -eq 'image' -and $args[1] -eq 'inspect') { Write-Output 'sha256:kylin'; $global:LASTEXITCODE=0; return }
if ($args[0] -eq 'compose') {
  if ($args -contains 'version') { Write-Output 'Docker Compose version v5.3.1'; $global:LASTEXITCODE=0; return }
  if ($args -contains 'pull' -and $env:DOCKER_MODE -eq 'materialization-hang') { Start-Sleep -Seconds 30; $global:LASTEXITCODE=0; return }
  if ($args -contains 'pull' -and $env:DOCKER_MODE -eq 'materialization-transient' -and ([regex]::Matches($history, ' pull asset-builder postgres frontend')).Count -eq 1) { $global:LASTEXITCODE=41; return }
  if ($args -contains 'build' -and $env:DOCKER_MODE -eq 'materialization-transient') { $global:LASTEXITCODE=41; return }
  if ($args -contains 'up' -and $args -contains 'bootstrap' -and $env:DOCKER_MODE -eq 'asset-build-slow-success') { $global:LASTEXITCODE=41; return }
  if ($args -contains 'build' -and $env:DOCKER_MODE -eq 'build-hang') { Start-Sleep -Seconds 30; $global:LASTEXITCODE=0; return }
  if ($args -contains 'config' -or $args -contains 'pull' -or $args -contains 'build' -or $args -contains 'up') { $global:LASTEXITCODE=0; return }
  if ($args -contains 'ps') {
    $service = $args[-1]
    $ids = @{ 'asset-builder'='builder-id'; bootstrap='bootstrap-id'; postgres='postgres-id'; oidc='oidc-id'; controlplane='controlplane-id'; agent='agent-id'; frontend='frontend-id' }
    if ($ids.ContainsKey($service)) { Write-Output $ids[$service] }
    $global:LASTEXITCODE=0; return
  }
  if ($args -contains 'run') {
    $joined = $args -join ' '
    if ($joined -match 'acceptance-runner normal$') { Write-Output 'runner-normal-id' }
    elseif ($joined -match 'acceptance-runner unauthorized$') { Write-Output 'runner-unauthorized-id' }
    elseif ($joined -match 'acceptance-runner post-restart$') { Write-Output 'runner-post-id' }
    elseif ($joined -match 'ROGUE_KIND=untrusted.*acceptance-runner rogue$') { Write-Output 'runner-rogue-untrusted-id' }
    elseif ($joined -match 'ROGUE_KIND=mismatch.*acceptance-runner rogue$') { Write-Output 'runner-rogue-mismatch-id' }
    elseif ($joined -match 'rogue-untrusted$') { Write-Output 'rogue-untrusted-id' }
    elseif ($joined -match 'rogue-mismatch$') { Write-Output 'rogue-mismatch-id' }
    elseif ($joined -match 'DBPILOT_ASSERTION_PHASE=replay.*assertions$') { Write-Output 'assertion-replay-id' }
    elseif ($joined -match 'DBPILOT_ASSERTION_PHASE=journal.*assertions$') { Write-Output 'assertion-journal-id' }
    elseif ($joined -match 'DBPILOT_ASSERTION_PHASE=summary.*assertions$') { Write-Output 'assertion-summary-id' }
    elseif ($joined -match 'DBPILOT_ASSERTION_PHASE=database.*assertions$') {
      $count = ([regex]::Matches($history, 'DBPILOT_ASSERTION_PHASE=database.*assertions')).Count
      Write-Output $(if ($count -le 1) { 'assertion-initial-id' } else { 'assertion-final-id' })
    }
    else { $global:LASTEXITCODE=41; return }
    $global:LASTEXITCODE=0; return
  }
}
if ($args[0] -eq 'ps') {
  if ($env:DOCKER_MODE -eq 'runid-collision') {
    $sentinel = Join-Path $env:COLLISION_TEMP_PARENT ('.tmp-full-stack-' + $env:DBPILOT_ACCEPTANCE_RUN_ID)
    New-Item -ItemType Directory -Path $sentinel -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $sentinel 'sentinel.txt'), 'pre-existing sentinel')
    Write-Output 'collision-existing-id'
    $global:LASTEXITCODE=0; return
  }
  if ($args -contains 'label=dbpilot.verifier=full-stack-compose') {
    if ($env:DOCKER_MODE -eq 'build-hang') { $global:LASTEXITCODE=0; return }
    if ($history -match '(?m)^rm -f -v agent-id\r?$') { $global:LASTEXITCODE=0; return }
    foreach ($id in $containers) {
      if ($env:DOCKER_MODE -eq 'container-label-mismatch' -and $id -eq 'runner-normal-id' -and $history -notmatch 'acceptance-runner normal') { continue }
      if ((CreatedContainer $id) -and (Present 'container' $id)) { Write-Output $id }
    }
  }
  $global:LASTEXITCODE=0; return
}
if ($args[0] -eq 'network' -and $args[1] -eq 'ls') {
  if ($args -notcontains 'label=dbpilot.verifier=full-stack-compose') { $global:LASTEXITCODE=0; return }
  if ($env:DOCKER_MODE -eq 'build-hang') { $global:LASTEXITCODE=0; return }
  if ($history -match '(?m)^network rm network-acceptance\r?$') { $global:LASTEXITCODE=0; return }
  foreach ($id in $networks) { if ((CreatedNetwork $id) -and (Present 'network' $id)) { Write-Output $id } }
  $global:LASTEXITCODE=0; return
}
if ($args[0] -eq 'volume' -and $args[1] -eq 'ls') {
  if ($args -notcontains 'label=dbpilot.verifier=full-stack-compose') { $global:LASTEXITCODE=0; return }
  if ($env:DOCKER_MODE -eq 'build-hang') { $global:LASTEXITCODE=0; return }
  if ($history -match '(?m)^volume rm volume-agent\r?$') { $global:LASTEXITCODE=0; return }
  foreach ($id in $volumes) { if ((CreatedVolume $id) -and (Present 'volume' $id)) { Write-Output $id } }
  $global:LASTEXITCODE=0; return
}
if ($args[0] -eq 'inspect') {
  if ($args -contains '{{json .State}}') {
    $id = $args[-1]
    if ($id -eq 'builder-id' -and $env:DOCKER_MODE -eq 'asset-build-timeout') { Write-Output '{"Status":"running","ExitCode":0}'; $global:LASTEXITCODE=0; return }
    if ($id -eq 'builder-id' -and $env:DOCKER_MODE -eq 'asset-build-slow-success') {
      $observations = ([regex]::Matches($history, 'inspect --format \{\{json \.State\}\} builder-id')).Count
      if ($observations -le 2) { Write-Output '{"Status":"running","ExitCode":0}'; $global:LASTEXITCODE=0; return }
    }
    if ($env:DOCKER_MODE -eq 'one-shot-hang' -and $id -eq 'bootstrap-id') { Write-Output '{"Status":"running","ExitCode":0}'; $global:LASTEXITCODE=0; return }
    $code = if ($env:DOCKER_MODE -eq 'phase-failure' -and $id -eq 'runner-normal-id') { 19 }
      elseif ($env:DOCKER_MODE -eq 'post-download-failure' -and $id -eq 'assertion-initial-id') { 31 }
      elseif ($env:DOCKER_MODE -eq 'replay-failure' -and $id -eq 'assertion-replay-id') { 23 }
      elseif ($env:DOCKER_MODE -eq 'final-database-failure' -and $id -eq 'assertion-final-id') { 29 }
      elseif ($id -in @('rogue-untrusted-id','rogue-mismatch-id')) { 1 }
      else { 0 }
    Write-Output ('{"Status":"exited","ExitCode":' + $code + '}'); $global:LASTEXITCODE=0; return
  }
  if ($args -contains '--format') { Write-Output 'healthy'; $global:LASTEXITCODE=0; return }
  $id = $args[-1]
  if (-not (Present 'container' $id)) { $global:LASTEXITCODE=1; return }
  $mounts = if ($id -eq 'agent-id') { @(@{Type='volume';Name='volume-agent'}) } else { @() }
  $run = if ($env:DOCKER_MODE -eq 'container-label-mismatch' -and $id -eq 'runner-normal-id') { 'other-run' } else { $env:DBPILOT_ACCEPTANCE_RUN_ID }
  @{Id=$id;Config=@{Labels=@{'dbpilot.verifier'='full-stack-compose';'dbpilot.run'=$run}};Mounts=$mounts} | ConvertTo-Json -Depth 5
  $global:LASTEXITCODE=0; return
}
if ($args[0] -eq 'network' -and $args[1] -eq 'inspect') {
  $id = $args[-1]
  if (-not (Present 'network' $id)) { $global:LASTEXITCODE=1; return }
  $run = if ($env:DOCKER_MODE -eq 'network-label-mismatch' -and $id -eq 'network-acceptance') { 'other-run' } else { $env:DBPILOT_ACCEPTANCE_RUN_ID }
  @{Id=$id;Labels=@{'dbpilot.verifier'='full-stack-compose';'dbpilot.run'=$run}} | ConvertTo-Json -Depth 4
  $global:LASTEXITCODE=0; return
}
if ($args[0] -eq 'volume' -and $args[1] -eq 'inspect') {
  $id = $args[-1]
  if (-not (Present 'volume' $id)) { $global:LASTEXITCODE=1; return }
  $run = if ($env:DOCKER_MODE -eq 'label-mismatch' -and $id -eq 'volume-agent') { 'other-run' } else { $env:DBPILOT_ACCEPTANCE_RUN_ID }
  @{Name=$id;Labels=@{'dbpilot.verifier'='full-stack-compose';'dbpilot.run'=$run}} | ConvertTo-Json -Depth 4
  $global:LASTEXITCODE=0; return
}
if ($args[0] -eq 'port') { Write-Output '127.0.0.1:49177'; $global:LASTEXITCODE=0; return }
if ($args[0] -eq 'wait') {
  if ($env:DOCKER_MODE -eq 'one-shot-hang' -and $args[1] -eq 'bootstrap-id') { Start-Sleep -Seconds 30; Write-Output '0'; $global:LASTEXITCODE=0; return }
  if ($env:DOCKER_MODE -eq 'phase-failure' -and $args[1] -eq 'runner-normal-id') { Write-Output '19' }
  elseif ($env:DOCKER_MODE -eq 'post-download-failure' -and $args[1] -eq 'assertion-initial-id') { Write-Output '31' }
  elseif ($env:DOCKER_MODE -eq 'replay-failure' -and $args[1] -eq 'assertion-replay-id') { Write-Output '23' }
  elseif ($env:DOCKER_MODE -eq 'final-database-failure' -and $args[1] -eq 'assertion-final-id') { Write-Output '29' }
  elseif ($args[1] -in @('rogue-untrusted-id','rogue-mismatch-id')) { Write-Output '1' }
  else { Write-Output '0' }
  $global:LASTEXITCODE=0; return
}
if ($args[0] -eq 'logs') {
  if ($args[-1] -eq 'rogue-untrusted-id') { Write-Output 'x509: certificate signed by unknown authority' }
  elseif ($args[-1] -eq 'rogue-mismatch-id') { Write-Output 'rpc error: code = PermissionDenied Hello Agent ID differs from verified SPIFFE identity' }
  elseif ($args[-1] -eq 'frontend-id' -and $env:DOCKER_MODE -eq 'post-download-failure') { Write-Output '10.0.0.8 - - [30/Aug/2026:05:00:00 +0800] "GET /api/v1/artifact-downloads/artifact-acceptance?signature=9f97e5c83aef729d06e8078ec2a458102a70b024f4501a366c0f24e93626a0d1 HTTP/1.1" 200 128 "-" "Chromium"' }
  elseif ($args[-1] -eq 'assertion-initial-id' -and $env:DOCKER_MODE -eq 'post-download-failure') { [Console]::Error.WriteLine('post-download assertion failed safely') }
  elseif ($args[-1] -eq 'assertion-summary-id' -and $env:DOCKER_MODE -eq 'summary-leak') { Write-Output '{"run_id":"run-1","job_id":"job-1","online_command_id":"command-online","offline_command_id":"command-offline","report_id":"report-1","target_count":2,"finding_count":13,"report_count":1,"artifact_count":2,"audit_count":4,"controlplane_stopped_at":"2026-08-29T04:00:10Z","controlplane_restarted_at":"2026-08-29T04:01:00Z","token":"Bearer eyJsecret.payload.signature"}' }
  elseif ($args[-1] -eq 'assertion-summary-id') { Write-Output '{"run_id":"run-1","job_id":"job-1","online_command_id":"command-online","offline_command_id":"command-offline","report_id":"report-1","target_count":2,"finding_count":13,"report_count":1,"artifact_count":2,"audit_count":4,"controlplane_stopped_at":"2026-08-29T04:00:10Z","controlplane_restarted_at":"2026-08-29T04:01:00Z"}' }
  elseif ($env:DOCKER_MODE -eq 'phase-failure') { [Console]::Error.WriteLine('browser stderr diagnostic Bearer eyJsecret.header.signature postgres://user:password@postgres/db') }
  else { Write-Output 'bounded safe log' }
  $global:LASTEXITCODE=0; return
}
if ($args[0] -eq 'stop' -or $args[0] -eq 'start' -or $args[0] -eq 'cp') { $global:LASTEXITCODE=0; return }
if ($args[0] -eq 'rm') { $global:LASTEXITCODE=0; return }
if ($args[0] -eq 'network' -and $args[1] -eq 'rm') { $global:LASTEXITCODE=0; return }
if ($args[0] -eq 'volume' -and $args[1] -eq 'rm') { $global:LASTEXITCODE=0; return }
$global:LASTEXITCODE=42
`;
  const executableSource = source
    .replaceAll('$global:LASTEXITCODE=0; return', 'exit 0')
    .replaceAll('$global:LASTEXITCODE=1; return', 'exit 1')
    .replaceAll('$global:LASTEXITCODE=17; return', 'exit 17')
    .replaceAll('$global:LASTEXITCODE=41; return', 'exit 41')
    .replaceAll('$global:LASTEXITCODE=42', 'exit 42');
  await writeFile(docker, executableSource);
  await writeFile(go, "Write-Output 'go version go1.27.0 windows/amd64'\n$global:LASTEXITCODE=0\n");
  return { root, docker, go, log, mode };
}

function verifierArguments(fixture, image = approvedImage) {
  return ['-File', verifier, '-Image', image, '-Architecture', 'amd64', '-DockerBinary', fixture.docker, '-GoBinary', fixture.go, '-OutageSeconds', '0', '-FailureArtifactRoot', fixture.root];
}

function boundedVerifierArguments(fixture) {
  return [...verifierArguments(fixture), '-DockerCommandTimeoutSeconds', '2', '-BuildTimeoutSeconds', '1', '-JobTimeoutSeconds', '1'];
}

function coldStartVerifierArguments(fixture, { materialize = 1, assetBuild = 4 } = {}) {
  return [...boundedVerifierArguments(fixture), '-MaterializeTimeoutSeconds', String(materialize), '-AssetBuildTimeoutSeconds', String(assetBuild)];
}

async function assertSignatureRedaction(shell) {
  const source = await readFile(verifier, 'utf8');
  const start = source.indexOf('function Redact-Text {');
  const end = source.indexOf('function Save-BoundedContainerLog {', start);
  assert.ok(start >= 0 && end > start, 'Redact-Text function boundary is unavailable');
  const root = await mkdtemp(join(tmpdir(), 'dbpilot-redactor-test-'));
  const script = join(root, 'redact.ps1');
  try {
    await writeFile(script, `${source.slice(start, end)}\n[Console]::Out.Write((Redact-Text ([Console]::In.ReadToEnd())))\n`);
    const cases = [
      ['GET /download?signature=abc123 HTTP/1.1', 'GET /download?signature=[REDACTED] HTTP/1.1'],
      ['SIGNATURE=AbC%2BDef%3D&format=json', 'SIGNATURE=[REDACTED]&format=json'],
      ['?format=html&Signature=middle_value-9&download=1', '?format=html&Signature=[REDACTED]&download=1'],
      ['prefix signature=value; status=403', 'prefix signature=[REDACTED]; status=403'],
      ['fixed diagnostic: signature verification failed safely', 'fixed diagnostic: signature verification failed safely'],
    ];
    for (const [input, expected] of cases) {
      const result = spawnSync(shell, ['-NoProfile', '-File', script], { encoding: 'utf8', input, timeout: 10_000 });
      if (result.status !== 0 || result.stdout !== expected || result.stderr !== '') {
        assert.fail('signature redaction produced an unsafe or damaged fixed diagnostic');
      }
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('verifier rejects an unapproved Kylin image before invoking Docker', async () => {
  const fixture = await fakeRuntime();
  try {
    const result = pwsh(verifierArguments(fixture, 'kylin:latest'), { DOCKER_LOG: fixture.log });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, new RegExp(approvedImage.replaceAll('.', '\\.')));
    await assert.rejects(readFile(fixture.log, 'utf8'), { code: 'ENOENT' });
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('verifier refuses an exact run-label collision before creation and preserves the colliding sentinel directory', async () => {
  const fixture = await fakeRuntime('runid-collision');
  let sentinel;
  try {
    const collisionParent = join(repoRoot, 'backend');
    const result = pwsh(verifierArguments(fixture), {
      DOCKER_LOG: fixture.log,
      DOCKER_MODE: fixture.mode,
      DBPILOT_FULL_STACK_TEST_MODE: '1',
      COLLISION_TEMP_PARENT: collisionParent,
    });
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}\n${result.stderr}`, /run ownership collision/i);
    const invocations = await readFile(fixture.log, 'utf8');
    const run = invocations.match(/label=dbpilot\.run=([0-9a-f]{32})/)?.[1];
    assert.ok(run, invocations);
    sentinel = join(collisionParent, `.tmp-full-stack-${run}`);
    assert.equal(await readFile(join(sentinel, 'sentinel.txt'), 'utf8'), 'pre-existing sentinel');
    assert.doesNotMatch(invocations, /^compose .* (?:build|up|run) |^(?:start|stop|rm|network rm|volume rm) /m);
  } finally {
    if (sentinel) await rm(sentinel, { recursive: true, force: true });
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('verifier owns one unique project, preserves phase order, records the ephemeral port, and cleans exact resources', async () => {
  const fixture = await fakeRuntime();
  try {
    const environment = { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' };
    const result = pwsh(verifierArguments(fixture), environment);
    const invocations = await readFile(fixture.log, 'utf8');
    assert.equal(result.status, 0, `${result.stderr || result.stdout}\n${invocations}`);
    const projectNames = [...invocations.matchAll(/(?:--project-name|-p) (dbpilot-full-stack-[0-9a-f]{32})/g)].map((match) => match[1]);
    assert.ok(projectNames.length > 5, invocations);
    assert.equal(new Set(projectNames).size, 1, 'every Compose call must use the same unique project');
    assert.match(invocations, /port frontend-id 8443\/tcp/);
    assert.match(result.stdout, /frontend_port=49177/);
    assert.match(invocations, /cp .* runner-post-id:\/acceptance\/artifacts\/rogue-untrusted\.log/, 'rogue evidence must use the direct writable Artifact mount');
    assert.match(invocations, /cp .* runner-post-id:\/acceptance\/artifacts\/rogue-mismatch\.log/);
    assert.doesNotMatch(invocations, /cp .* controlplane-id:\/acceptance\/state\/artifacts\//, 'docker cp cannot traverse a read-only parent mount');
    const pull = invocations.indexOf(' pull asset-builder postgres frontend');
    const build = invocations.indexOf(' build acceptance-runner');
    const firstUp = invocations.indexOf(' up --pull never -d --no-deps asset-builder');
    assert.ok(pull >= 0 && pull < build && build < firstUp, invocations);
    for (const line of invocations.split(/\r?\n/).filter((value) => value.includes(' up '))) {
      assert.match(line, / up --pull never /, `up escaped explicit pull policy: ${line}`);
    }
    assert.doesNotMatch(invocations, / pull .*?(?:bootstrap|oidc|controlplane|agent|rogue|assertions)/);
    const milestones = [
      'OIDC acceptance passed',
      'Agent mTLS communication passed',
      'Host inspection browser acceptance passed',
      'Control-plane restart and spool recovery passed',
      'Full-stack success summary:',
      'Rogue Agent rejection passed',
      'Database and journal assertions passed',
      'Full-stack cleanup audit passed',
    ];
    let milestoneCursor = -1;
    for (const milestone of milestones) {
      milestoneCursor = result.stdout.indexOf(milestone, milestoneCursor + 1);
      assert.notEqual(milestoneCursor, -1, `missing or out-of-order milestone: ${milestone}\n${result.stdout}`);
    }

    const ordered = [
      'acceptance-runner normal',
      'acceptance-runner unauthorized',
      'DBPILOT_ASSERTION_PHASE=database',
      'stop --time 20 controlplane-id',
      'start controlplane-id',
      'acceptance-runner post-restart',
      'rogue-untrusted',
      'ROGUE_KIND=untrusted',
      'rogue-mismatch',
      'ROGUE_KIND=mismatch',
      'stop --time 20 agent-id',
      'DBPILOT_ASSERTION_PHASE=replay',
      'DBPILOT_ASSERTION_PHASE=journal',
      'DBPILOT_ASSERTION_PHASE=database',
      'DBPILOT_ASSERTION_PHASE=summary',
    ];
    let cursor = -1;
    for (const marker of ordered) {
      cursor = invocations.indexOf(marker, cursor + 1);
      assert.notEqual(cursor, -1, `missing or out-of-order phase: ${marker}\n${invocations}`);
    }

    for (const id of ['controlplane-id', 'agent-id', 'frontend-id', 'runner-normal-id']) {
      assert.match(invocations, new RegExp(`^rm -f -v ${id}$`, 'm'));
    }
    for (const id of ['network-acceptance', 'network-builder']) {
      assert.match(invocations, new RegExp(`^network rm ${id}$`, 'm'));
    }
    for (const id of ['volume-bin', 'volume-agent', 'volume-rogue-mismatch']) {
      assert.match(invocations, new RegExp(`^volume rm ${id}$`, 'm'));
    }
    assert.doesNotMatch(invocations, /preexisting-similar-id|\bdown\b|\bprune\b|\*.*(?:rm|remove)|(?:rm|remove).*\*/i);
    assert.match(`${result.stdout}\n${result.stderr}`, /Full-stack cleanup audit passed/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('verifier propagates a phase failure, emits only redacted failure artifacts, and still cleans', async () => {
  const fixture = await fakeRuntime('phase-failure');
  try {
    const result = pwsh(verifierArguments(fixture), { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.notEqual(result.status, 0);
    const combined = `${result.stdout}\n${result.stderr}`;
    assert.match(combined, /Full-stack failure artifacts:/);
    assert.match(combined, /Full-stack cleanup audit passed/);
    assert.doesNotMatch(combined, /eyJsecret|user:password|Bearer\s+\S+/i);
    const failureDirectory = (await readdir(fixture.root, { withFileTypes: true }))
      .find((entry) => entry.isDirectory() && entry.name.startsWith('dbpilot-full-stack-failure-'));
    assert.ok(failureDirectory, 'failure artifact directory was not retained');
    const failurePath = join(fixture.root, failureDirectory.name);
    const logFiles = (await readdir(failurePath, { withFileTypes: true })).filter((entry) => entry.isFile() && entry.name.endsWith('.log'));
    const artifactText = (await Promise.all(logFiles.map((entry) => readFile(join(failurePath, entry.name), 'utf8')))).join('\n');
    assert.match(artifactText, /browser stderr diagnostic/);
    assert.doesNotMatch(artifactText, /eyJsecret|user:password|Bearer\s+eyJ/i);
    const invocations = await readFile(fixture.log, 'utf8');
    assert.match(invocations, /^rm -f -v runner-normal-id$/m);
    assert.match(invocations, /cp runner-normal-id:\/acceptance\/artifacts\/playwright\/\./);
    assert.doesNotMatch(invocations, /acceptance-runner post-restart/);
    assert.doesNotMatch(invocations, /preexisting-similar-id|\bdown\b|\bprune\b/i);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

async function assertPostDownloadFailureArtifacts(runVerifier) {
  const fixture = await fakeRuntime('post-download-failure');
  const hmac = '9f97e5c83aef729d06e8078ec2a458102a70b024f4501a366c0f24e93626a0d1';
  try {
    const result = runVerifier(verifierArguments(fixture), { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.notEqual(result.status, 0);
    const failureDirectory = (await readdir(fixture.root, { withFileTypes: true }))
      .find((entry) => entry.isDirectory() && entry.name.startsWith('dbpilot-full-stack-failure-'));
    assert.ok(failureDirectory, 'post-download failure artifacts were not retained');
    const failurePath = join(fixture.root, failureDirectory.name);
    const retained = await readdir(failurePath, { recursive: true, withFileTypes: true });
    const retainedBodies = await Promise.all(retained.filter((entry) => entry.isFile()).map((entry) => readFile(join(entry.parentPath, entry.name))));
    const retainedBytes = Buffer.concat(retainedBodies);
    const retainedText = retainedBytes.toString('utf8');
    assert.equal(retainedBytes.includes(Buffer.from(hmac)), false, 'retained failure artifact contains the Artifact HMAC');
    assert.doesNotMatch(retainedText, /signature=(?!\[REDACTED\])[^&\s"'<>#;]+/i);
    assert.match(retainedText, /GET \/api\/v1\/artifact-downloads\/artifact-acceptance\?signature=\[REDACTED\] HTTP\/1\.1" 200/);
    assert.match(retainedText, /post-download assertion failed safely/);
    assert.match(`${result.stdout}\n${result.stderr}`, /Full-stack cleanup audit passed/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
}

test('post-download failure retains a safe Artifact path and status without signature query values', async () => {
  await assertPostDownloadFailureArtifacts(pwsh);
});

test('Windows PowerShell 5.1 redacts signed Artifact URLs from post-download failure artifacts', { skip: !existsSync(windowsPowerShellBinary) }, async () => {
  await assertPostDownloadFailureArtifacts(windowsPowerShell);
});

test('bounded Docker failures retain redacted stderr diagnostics', async () => {
  const source = await readFile(verifier, 'utf8');
  assert.match(source, /function Get-DockerFailureMessage/);
  assert.match(source, /Get-DockerFailureMessage[^]*\.Stdout[^]*\.Stderr[^]*Redact-Text/);
  assert.match(source, /Get-DockerFailureMessage[^]*4096/);
});

test('Redact-Text removes signed URL values without damaging fixed diagnostics', async () => {
  await assertSignatureRedaction('pwsh');
});

test('Windows PowerShell 5.1 Redact-Text removes signed URL values without damaging fixed diagnostics', { skip: !existsSync(windowsPowerShellBinary) }, async () => {
  await assertSignatureRedaction(windowsPowerShellBinary);
});

test('verifier never removes a recorded volume whose ownership labels do not match', async () => {
  const fixture = await fakeRuntime('label-mismatch');
  try {
    const result = pwsh(verifierArguments(fixture), { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.notEqual(result.status, 0);
    const invocations = await readFile(fixture.log, 'utf8');
    assert.doesNotMatch(invocations, /^volume rm volume-agent$/m);
    assert.doesNotMatch(invocations, /\bdown\b|\bprune\b/i);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('verifier audits but never removes a newly observed container whose ownership labels mismatch', async () => {
  const fixture = await fakeRuntime('container-label-mismatch');
  try {
    const result = pwsh(verifierArguments(fixture), { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}\n${result.stderr}`, /Recorded container 'runner-normal-id' remains after cleanup/);
    const invocations = await readFile(fixture.log, 'utf8');
    assert.doesNotMatch(invocations, /^rm -f -v runner-normal-id$/m);
    assert.match(invocations, /inspect runner-normal-id/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('verifier audits but never removes an observed network whose ownership labels mismatch', async () => {
  const fixture = await fakeRuntime('network-label-mismatch');
  try {
    const result = pwsh(verifierArguments(fixture), { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}\n${result.stderr}`, /Recorded network 'network-acceptance' remains after cleanup/);
    const invocations = await readFile(fixture.log, 'utf8');
    assert.doesNotMatch(invocations, /^network rm network-acceptance$/m);
    assert.match(invocations, /network inspect network-acceptance/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('verifier does not claim spool recovery until the stopped-Agent replay assertion passes', async () => {
  const fixture = await fakeRuntime('replay-failure');
  try {
    const result = pwsh(verifierArguments(fixture), { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.stdout, /Control-plane restart and spool recovery passed/);
    assert.match(result.stdout, /Full-stack cleanup audit passed/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('verifier does not claim rogue persistence or final assertions before the final database check passes', async () => {
  const fixture = await fakeRuntime('final-database-failure');
  try {
    const result = pwsh(verifierArguments(fixture), { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.stdout, /Rogue Agent rejection passed|Database and journal assertions passed/);
    assert.doesNotMatch(result.stdout, /Full-stack success summary:/);
    assert.match(result.stdout, /Control-plane restart and spool recovery passed/);
    assert.match(result.stdout, /Full-stack cleanup audit passed/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('success summary prints only allowlisted validated state after final assertions', async () => {
  const fixture = await fakeRuntime();
  try {
    const result = pwsh(verifierArguments(fixture), { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const match = result.stdout.match(/Full-stack success summary: (\{[^\r\n]+\})/);
    assert.ok(match, result.stdout);
    assert.deepEqual(JSON.parse(match[1]), {
      run_id: 'run-1', job_id: 'job-1', online_command_id: 'command-online', offline_command_id: 'command-offline', report_id: 'report-1',
      target_count: 2, finding_count: 13, report_count: 1, artifact_count: 2, audit_count: 4,
      controlplane_stopped_at: '2026-08-29T04:00:10.000Z', controlplane_restarted_at: '2026-08-29T04:01:00.000Z',
    });
    const invocations = await readFile(fixture.log, 'utf8');
    assert.ok(invocations.lastIndexOf('DBPILOT_ASSERTION_PHASE=summary') > invocations.lastIndexOf('DBPILOT_ASSERTION_PHASE=database'));
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('success summary rejects unknown fields without printing sensitive values', async () => {
  const fixture = await fakeRuntime('summary-leak');
  try {
    const result = pwsh(verifierArguments(fixture), { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.stdout, /Full-stack success summary:|eyJsecret|Bearer\s+\S+/i);
    assert.match(`${result.stdout}\n${result.stderr}`, /Full-stack cleanup audit passed/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('verifier restores caller Compose environment values after failure', async () => {
  const fixture = await fakeRuntime('phase-failure');
  try {
    const command = `$env:DBPILOT_ACCEPTANCE_PROJECT='sentinel-project'; $env:DBPILOT_ACCEPTANCE_RUN_ID='sentinel-run'; try { & '${verifier}' -Image '${approvedImage}' -Architecture amd64 -DockerBinary '${fixture.docker}' -GoBinary '${fixture.go}' -OutageSeconds 0 -FailureArtifactRoot '${fixture.root}' } catch {}; Write-Output ('RESTORED=' + $env:DBPILOT_ACCEPTANCE_PROJECT + '|' + $env:DBPILOT_ACCEPTANCE_RUN_ID)`;
    const result = pwsh(['-Command', command], { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /RESTORED=sentinel-project\|sentinel-run/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('verifier owns and terminates a hung Compose build before restoring its environment', async () => {
  const fixture = await fakeRuntime('build-hang');
  try {
    const call = `& '${verifier}' ${boundedVerifierArguments(fixture).slice(2).map((value) => value.startsWith('-') ? value : `'${value.replaceAll("'", "''")}'`).join(' ')}`;
    const command = `$env:DBPILOT_ACCEPTANCE_PROJECT='sentinel-project'; $env:DBPILOT_ACCEPTANCE_RUN_ID='sentinel-run'; try { ${call} } catch { Write-Output ('FIXED=' + $_.Exception.Message) }; Write-Output ('RESTORED=' + $env:DBPILOT_ACCEPTANCE_PROJECT + '|' + $env:DBPILOT_ACCEPTANCE_RUN_ID)`;
    const started = Date.now();
    const result = pwsh(['-Command', command], { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    const elapsed = Date.now() - started;
    assert.equal(result.status, 0, result.stderr);
    assert.ok(elapsed < 15_000, `hung build was not terminated: ${elapsed}ms`);
    assert.match(result.stdout, /FIXED=The acceptance-runner image build timed out\./);
    assert.match(result.stdout, /RESTORED=sentinel-project\|sentinel-run/);
    const invocations = await readFile(fixture.log, 'utf8');
    assert.match(invocations, /compose .* build acceptance-runner/);
    assert.doesNotMatch(invocations, /compose .* up /);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('verifier terminates a hung public-image materialization phase before build and restores environment', async () => {
  const fixture = await fakeRuntime('materialization-hang');
  try {
    const tokens = coldStartVerifierArguments(fixture).slice(2).map((value) => value.startsWith('-') ? value : `'${value.replaceAll("'", "''")}'`).join(' ');
    const command = `$env:DBPILOT_ACCEPTANCE_PROJECT='sentinel-project'; $env:DBPILOT_ACCEPTANCE_RUN_ID='sentinel-run'; try { & '${verifier}' ${tokens} } catch { Write-Output ('FIXED=' + $_.Exception.Message) }; Write-Output ('RESTORED=' + $env:DBPILOT_ACCEPTANCE_PROJECT + '|' + $env:DBPILOT_ACCEPTANCE_RUN_ID)`;
    const result = pwsh(['-Command', command], { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /FIXED=Public acceptance image materialization timed out\./);
    assert.match(result.stdout, /RESTORED=sentinel-project\|sentinel-run/);
    const invocations = await readFile(fixture.log, 'utf8');
    assert.match(invocations, / pull asset-builder postgres frontend/);
    assert.doesNotMatch(invocations, / build acceptance-runner| up /);
    const run = invocations.match(/label=dbpilot\.run=([0-9a-f]{32})/)?.[1];
    assert.ok(run, invocations);
    assert.equal(existsSync(join(repoRoot, 'backend', `.tmp-full-stack-${run}`)), false);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('verifier retries the exact public-image materialization once before build', async () => {
  const fixture = await fakeRuntime('materialization-transient');
  try {
    const result = pwsh(verifierArguments(fixture), { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.notEqual(result.status, 0, 'the fake runner build intentionally stops after materialization');
    const invocations = await readFile(fixture.log, 'utf8');
    assert.equal((invocations.match(/ pull asset-builder postgres frontend/g) ?? []).length, 2, invocations);
    assert.equal((invocations.match(/ build acceptance-runner/g) ?? []).length, 1, invocations);
    assert.match(result.stdout, /Full-stack cleanup audit passed/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('asset builder can exceed the generic job deadline while remaining inside its dedicated deadline', async () => {
  const fixture = await fakeRuntime('asset-build-slow-success');
  try {
    const result = pwsh(coldStartVerifierArguments(fixture, { assetBuild: 4 }), { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.notEqual(result.status, 0, 'the fake bootstrap start intentionally fails after the builder proves its separate deadline');
    assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /asset-builder did not exit before the deadline/);
    const invocations = await readFile(fixture.log, 'utf8');
    assert.ok((invocations.match(/inspect --format \{\{json \.State\}\} builder-id/g) ?? []).length >= 3, invocations);
    assert.match(invocations, /^rm -f -v builder-id$/m);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('asset builder dedicated deadline still times out and cleans exact resources', async () => {
  const fixture = await fakeRuntime('asset-build-timeout');
  try {
    const result = pwsh(coldStartVerifierArguments(fixture, { assetBuild: 1 }), { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}\n${result.stderr}`, /asset-builder did not exit before the deadline/);
    assert.match(result.stdout, /Full-stack cleanup audit passed/);
    const invocations = await readFile(fixture.log, 'utf8');
    assert.match(invocations, /^rm -f -v builder-id$/m);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('verifier times out a running one-shot container without docker wait and cleans its exact resources', async () => {
  const fixture = await fakeRuntime('one-shot-hang');
  try {
    const tokens = boundedVerifierArguments(fixture).slice(2).map((value) => value.startsWith('-') ? value : `'${value.replaceAll("'", "''")}'`).join(' ');
    const command = `$env:DBPILOT_ACCEPTANCE_PROJECT='sentinel-project'; $env:DBPILOT_ACCEPTANCE_RUN_ID='sentinel-run'; try { & '${verifier}' ${tokens} } catch { Write-Output ('FIXED=' + $_.Exception.Message) }; Write-Output ('RESTORED=' + $env:DBPILOT_ACCEPTANCE_PROJECT + '|' + $env:DBPILOT_ACCEPTANCE_RUN_ID)`;
    const result = pwsh(['-Command', command], { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /FIXED=bootstrap did not exit before the deadline\./);
    assert.match(result.stdout, /RESTORED=sentinel-project\|sentinel-run/);
    const invocations = await readFile(fixture.log, 'utf8');
    assert.doesNotMatch(invocations, /^wait /m);
    assert.match(invocations, /^rm -f -v bootstrap-id$/m);
    assert.match(invocations, /^rm -f -v builder-id$/m);
    assert.match(invocations, /^network rm network-acceptance$/m);
    assert.match(invocations, /^network rm network-builder$/m);
    assert.match(invocations, /^volume rm volume-agent$/m);
    assert.match(invocations, /^volume rm volume-bin$/m);
    assert.doesNotMatch(invocations, / up --pull never -d --no-deps postgres oidc/);
    assert.match(result.stdout, /Full-stack cleanup audit passed/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('CI always runs fake-Docker safety and exposes the live verifier only as an explicit Windows opt-in', async () => {
  const source = await readFile(workflow, 'utf8');
  assert.match(source, /workflow_dispatch:\s*[\s\S]*run_full_stack:/);
  assert.match(source, /node --test tests\/contracts\/full-stack-container-safety\.test\.mjs/);
  assert.match(source, /docker compose -f backend\/docker\/full-stack\/docker-compose\.yml --profile '\*' config --quiet/);
  assert.match(source, /full-stack-acceptance:[\s\S]*if:.*run_full_stack[\s\S]*runs-on:\s*\[self-hosted, Windows, X64\]/);
  assert.match(source, /verify-full-stack-compose\.ps1[\s\S]*cr\.kylinos\.cn\/kylin\/kylin-server-platform:v10sp1/);
  assert.equal((source.match(/backend\/docker\/full-stack\/\*\*/g) ?? []).length, 2, 'topology changes must trigger both pull_request and push');
  assert.equal((source.match(/backend\/test\/e2e\/full-stack\/\*\*/g) ?? []).length, 2, 'runner changes must trigger both pull_request and push');
});

test('Windows PowerShell 5.1 runs fake success from tool paths containing spaces', { skip: !existsSync(windowsPowerShellBinary) }, async () => {
  const fixture = await fakeRuntime('success', { withSpaces: true });
  try {
    const result = windowsPowerShell(boundedVerifierArguments(fixture), { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.match(result.stdout, /Full-stack cleanup audit passed/);
    const invocations = await readFile(fixture.log, 'utf8');
    assert.match(invocations, /compose .* acceptance-runner normal/);
    assert.doesNotMatch(invocations, /^wait /m);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('Windows PowerShell 5.1 native quoting preserves empty, spaces, quotes, and trailing backslashes', { skip: !existsSync(windowsPowerShellBinary) }, () => {
  const escapedHelper = containerSafetyHelper.replaceAll("'", "''");
  const command = `. '${escapedHelper}'; @('', 'plain', 'with space', 'a"b', 'C:\\path with space\\') | ForEach-Object { ConvertTo-DBPilotNativeArgument $_ } | ConvertTo-Json -Compress`;
  const encoded = Buffer.from(command, 'utf16le').toString('base64');
  const result = windowsPowerShell(['-EncodedCommand', encoded]);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), ['""', 'plain', '"with space"', '"a\\"b"', '"C:\\path with space\\\\"']);
});

test('Windows PowerShell 5.1 kills a hung build and restores caller environment', { skip: !existsSync(windowsPowerShellBinary) }, async () => {
  const fixture = await fakeRuntime('build-hang', { withSpaces: true });
  try {
    const tokens = boundedVerifierArguments(fixture).slice(2).map((value) => value.startsWith('-') ? value : `'${value.replaceAll("'", "''")}'`).join(' ');
    const command = `$env:DBPILOT_ACCEPTANCE_PROJECT='sentinel-project'; $env:DBPILOT_ACCEPTANCE_RUN_ID='sentinel-run'; try { & '${verifier}' ${tokens} } catch { Write-Output ('FIXED=' + $_.Exception.Message) }; Write-Output ('RESTORED=' + $env:DBPILOT_ACCEPTANCE_PROJECT + '|' + $env:DBPILOT_ACCEPTANCE_RUN_ID)`;
    const result = windowsPowerShell(['-Command', command], { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /FIXED=The acceptance-runner image build timed out\./);
    assert.match(result.stdout, /RESTORED=sentinel-project\|sentinel-run/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('Windows PowerShell 5.1 bounds a running one-shot and cleans exact resources', { skip: !existsSync(windowsPowerShellBinary) }, async () => {
  const fixture = await fakeRuntime('one-shot-hang', { withSpaces: true });
  try {
    const tokens = boundedVerifierArguments(fixture).slice(2).map((value) => value.startsWith('-') ? value : `'${value.replaceAll("'", "''")}'`).join(' ');
    const command = `$env:DBPILOT_ACCEPTANCE_PROJECT='sentinel-project'; $env:DBPILOT_ACCEPTANCE_RUN_ID='sentinel-run'; try { & '${verifier}' ${tokens} } catch { Write-Output ('FIXED=' + $_.Exception.Message) }; Write-Output ('RESTORED=' + $env:DBPILOT_ACCEPTANCE_PROJECT + '|' + $env:DBPILOT_ACCEPTANCE_RUN_ID)`;
    const result = windowsPowerShell(['-Command', command], { DOCKER_LOG: fixture.log, DOCKER_MODE: fixture.mode, DBPILOT_FULL_STACK_TEST_MODE: '1' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /FIXED=bootstrap did not exit before the deadline\./);
    assert.match(result.stdout, /RESTORED=sentinel-project\|sentinel-run/);
    assert.match(result.stdout, /Full-stack cleanup audit passed/);
    const invocations = await readFile(fixture.log, 'utf8');
    assert.doesNotMatch(invocations, /^wait /m);
    assert.match(invocations, /^rm -f -v bootstrap-id$/m);
    assert.match(invocations, /^rm -f -v builder-id$/m);
    assert.match(invocations, /^network rm network-acceptance$/m);
    assert.match(invocations, /^network rm network-builder$/m);
    assert.match(invocations, /^volume rm volume-agent$/m);
    assert.match(invocations, /^volume rm volume-bin$/m);
    assert.doesNotMatch(invocations, / up --pull never -d --no-deps postgres oidc/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});
