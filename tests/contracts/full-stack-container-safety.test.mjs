import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const verifier = join(repoRoot, 'backend', 'scripts', 'verify-full-stack-compose.ps1');
const workflow = join(repoRoot, '.github', 'workflows', 'contracts.yml');
const approvedImage = 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1';

function pwsh(args, env = {}) {
  return spawnSync('pwsh', ['-NoProfile', ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: { ...process.env, ...env },
    timeout: 120_000,
  });
}

async function fakeRuntime(mode = 'success') {
  const root = await mkdtemp(join(tmpdir(), 'dbpilot-full-stack-fake-'));
  const docker = join(root, 'docker.ps1');
  const go = join(root, 'go.ps1');
  const log = join(root, 'docker.log');
  const source = String.raw`
$line = $args -join ' '
[IO.File]::AppendAllText($env:DOCKER_LOG, $line + [Environment]::NewLine)
$history = [IO.File]::ReadAllText($env:DOCKER_LOG)
$containers = @('builder-id','bootstrap-id','postgres-id','oidc-id','controlplane-id','agent-id','frontend-id','runner-normal-id','runner-unauthorized-id','assertion-initial-id','runner-post-id','rogue-untrusted-id','runner-rogue-untrusted-id','rogue-mismatch-id','runner-rogue-mismatch-id','assertion-replay-id','assertion-journal-id','assertion-final-id')
$volumes = @('volume-bin','volume-secrets','volume-config','volume-state','volume-artifacts','volume-agent','volume-runner','volume-go-cache','volume-rogue-untrusted','volume-rogue-mismatch')
$networks = @('network-acceptance','network-builder')
function Present([string]$kind, [string]$id) {
  if ($kind -eq 'container') { return $history -notmatch "(?m)^rm -f -v $([regex]::Escape($id))\r?$" }
  if ($kind -eq 'network') { return $history -notmatch "(?m)^network rm $([regex]::Escape($id))\r?$" }
  return $history -notmatch "(?m)^volume rm $([regex]::Escape($id))\r?$"
}
if ($args[0] -eq 'version') { Write-Output '29.7.2'; $global:LASTEXITCODE=0; return }
if ($args[0] -eq 'info') { Write-Output 'amd64'; $global:LASTEXITCODE=0; return }
if ($args[0] -eq 'image' -and $args[1] -eq 'inspect') { Write-Output 'sha256:kylin'; $global:LASTEXITCODE=0; return }
if ($args[0] -eq 'compose') {
  if ($args -contains 'version') { Write-Output 'Docker Compose version v5.3.1'; $global:LASTEXITCODE=0; return }
  if ($args -contains 'config' -or $args -contains 'build' -or $args -contains 'up') { $global:LASTEXITCODE=0; return }
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
    elseif ($joined -match 'DBPILOT_ASSERTION_PHASE=database.*assertions$') {
      $count = ([regex]::Matches($history, 'DBPILOT_ASSERTION_PHASE=database.*assertions')).Count
      Write-Output $(if ($count -le 1) { 'assertion-initial-id' } else { 'assertion-final-id' })
    }
    else { $global:LASTEXITCODE=41; return }
    $global:LASTEXITCODE=0; return
  }
}
if ($args[0] -eq 'ps') {
  if ($args -contains 'label=dbpilot.verifier=full-stack-compose') {
    if ($history -match '(?m)^rm -f -v agent-id\r?$') { $global:LASTEXITCODE=0; return }
    foreach ($id in $containers) { if (Present 'container' $id) { Write-Output $id } }
  }
  $global:LASTEXITCODE=0; return
}
if ($args[0] -eq 'network' -and $args[1] -eq 'ls') {
  if ($history -match '(?m)^network rm network-acceptance\r?$') { $global:LASTEXITCODE=0; return }
  foreach ($id in $networks) { if (Present 'network' $id) { Write-Output $id } }
  $global:LASTEXITCODE=0; return
}
if ($args[0] -eq 'volume' -and $args[1] -eq 'ls') {
  if ($history -match '(?m)^volume rm volume-agent\r?$') { $global:LASTEXITCODE=0; return }
  foreach ($id in $volumes) { if (Present 'volume' $id) { Write-Output $id } }
  $global:LASTEXITCODE=0; return
}
if ($args[0] -eq 'inspect') {
  if ($args -contains '--format') { Write-Output 'healthy'; $global:LASTEXITCODE=0; return }
  $id = $args[-1]
  if (-not (Present 'container' $id)) { $global:LASTEXITCODE=1; return }
  $mounts = if ($id -eq 'agent-id') { @(@{Type='volume';Name='volume-agent'}) } else { @() }
  @{Id=$id;Config=@{Labels=@{'dbpilot.verifier'='full-stack-compose';'dbpilot.run'=$env:DBPILOT_ACCEPTANCE_RUN_ID}};Mounts=$mounts} | ConvertTo-Json -Depth 5
  $global:LASTEXITCODE=0; return
}
if ($args[0] -eq 'network' -and $args[1] -eq 'inspect') {
  $id = $args[-1]
  if (-not (Present 'network' $id)) { $global:LASTEXITCODE=1; return }
  @{Id=$id;Labels=@{'dbpilot.verifier'='full-stack-compose';'dbpilot.run'=$env:DBPILOT_ACCEPTANCE_RUN_ID}} | ConvertTo-Json -Depth 4
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
  if ($env:DOCKER_MODE -eq 'phase-failure' -and $args[1] -eq 'runner-normal-id') { Write-Output '19' }
  elseif ($env:DOCKER_MODE -eq 'replay-failure' -and $args[1] -eq 'assertion-replay-id') { Write-Output '23' }
  elseif ($env:DOCKER_MODE -eq 'final-database-failure' -and $args[1] -eq 'assertion-final-id') { Write-Output '29' }
  elseif ($args[1] -in @('rogue-untrusted-id','rogue-mismatch-id')) { Write-Output '1' }
  else { Write-Output '0' }
  $global:LASTEXITCODE=0; return
}
if ($args[0] -eq 'logs') {
  if ($args[-1] -eq 'rogue-untrusted-id') { Write-Output 'x509: certificate signed by unknown authority' }
  elseif ($args[-1] -eq 'rogue-mismatch-id') { Write-Output 'rpc error: code = PermissionDenied Hello Agent ID differs from verified SPIFFE identity' }
  elseif ($env:DOCKER_MODE -eq 'phase-failure') { Write-Output 'Bearer eyJsecret.header.signature postgres://user:password@postgres/db' }
  else { Write-Output 'bounded safe log' }
  $global:LASTEXITCODE=0; return
}
if ($args[0] -eq 'stop' -or $args[0] -eq 'start' -or $args[0] -eq 'cp') { $global:LASTEXITCODE=0; return }
if ($args[0] -eq 'rm') { $global:LASTEXITCODE=0; return }
if ($args[0] -eq 'network' -and $args[1] -eq 'rm') { $global:LASTEXITCODE=0; return }
if ($args[0] -eq 'volume' -and $args[1] -eq 'rm') { $global:LASTEXITCODE=0; return }
$global:LASTEXITCODE=42
`;
  await writeFile(docker, source);
  await writeFile(go, "Write-Output 'go version go1.27.0 windows/amd64'\n$global:LASTEXITCODE=0\n");
  return { root, docker, go, log, mode };
}

function verifierArguments(fixture, image = approvedImage) {
  return ['-File', verifier, '-Image', image, '-Architecture', 'amd64', '-DockerBinary', fixture.docker, '-GoBinary', fixture.go, '-OutageSeconds', '0', '-FailureArtifactRoot', fixture.root];
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
    const milestones = [
      'OIDC acceptance passed',
      'Agent mTLS communication passed',
      'Host inspection browser acceptance passed',
      'Control-plane restart and spool recovery passed',
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
    assert.match(result.stdout, /Full-stack cleanup audit passed/);
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
    const invocations = await readFile(fixture.log, 'utf8');
    assert.match(invocations, /^rm -f -v runner-normal-id$/m);
    assert.match(invocations, /cp runner-normal-id:\/acceptance\/artifacts\/playwright\/\./);
    assert.doesNotMatch(invocations, /acceptance-runner post-restart/);
    assert.doesNotMatch(invocations, /preexisting-similar-id|\bdown\b|\bprune\b/i);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
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
    assert.match(result.stdout, /Control-plane restart and spool recovery passed/);
    assert.match(result.stdout, /Full-stack cleanup audit passed/);
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

test('CI always runs fake-Docker safety and exposes the live verifier only as an explicit Windows opt-in', async () => {
  const source = await readFile(workflow, 'utf8');
  assert.match(source, /workflow_dispatch:\s*[\s\S]*run_full_stack:/);
  assert.match(source, /node --test tests\/contracts\/full-stack-container-safety\.test\.mjs/);
  assert.match(source, /docker compose -f backend\/docker\/full-stack\/docker-compose\.yml --profile '\*' config --quiet/);
  assert.match(source, /full-stack-acceptance:[\s\S]*if:.*run_full_stack[\s\S]*runs-on:\s*\[self-hosted, Windows, X64\]/);
  assert.match(source, /verify-full-stack-compose\.ps1[\s\S]*cr\.kylinos\.cn\/kylin\/kylin-server-platform:v10sp1/);
});
