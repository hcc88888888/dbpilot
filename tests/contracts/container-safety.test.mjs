import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const helper = join(repoRoot, 'backend', 'scripts', 'container-safety.ps1');
const kylinVerifier = join(repoRoot, 'backend', 'scripts', 'verify-kylin-docker.ps1');

function pwsh(args, env = {}) {
  return spawnSync('pwsh', ['-NoProfile', ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
}

async function fakeDockerFixture() {
  const root = await mkdtemp(join(tmpdir(), 'dbpilot-container-safety-'));
  const docker = join(root, 'docker.ps1');
  const log = join(root, 'docker.log');
  const source = `
$line = $args -join ' '
[IO.File]::AppendAllText($env:DOCKER_LOG, $line + [Environment]::NewLine)
switch ($args[0]) {
  'ps' { if ($env:DOCKER_MODE -eq 'collision') { Write-Output 'preexisting-id' }; $global:LASTEXITCODE=0; return }
  'create' { if ($env:DOCKER_MODE -eq 'create-fails') { $global:LASTEXITCODE=17; return }; Write-Output 'created-id'; $global:LASTEXITCODE=0; return }
  'rm' { $global:LASTEXITCODE=0; return }
  default { $global:LASTEXITCODE=0; return }
}
`;
  await writeFile(docker, source);
  return { root, docker, log };
}

test('owned-container helper leaves a similarly named pre-existing container untouched', async () => {
  const fixture = await fakeDockerFixture();
  const command = `. '${helper}'; $id=$null; try { $id=New-DBPilotOwnedContainer -DockerBinary '${fixture.docker}' -Name 'dbpilot-contract-postgres-0123456789abcdef0123456789abcdef' -CreateArguments @('postgres:16-alpine') } finally { Remove-DBPilotOwnedContainer -DockerBinary '${fixture.docker}' -ContainerID $id }`;
  try {
    const result = pwsh(['-Command', command], { DOCKER_LOG: fixture.log, DOCKER_MODE: 'similar-exists' });
    assert.equal(result.status, 0, result.stderr);
    const invocations = await readFile(fixture.log, 'utf8');
    assert.match(invocations, /ps -a --filter name=\^\/dbpilot-contract-postgres-0123456789abcdef0123456789abcdef\$ --format \{\{\.ID\}\}/);
    assert.match(invocations, /rm -f -v created-id/);
    assert.doesNotMatch(invocations, /rm -f preexisting-id/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('owned-container removal deletes anonymous volumes from the recorded container only', async () => {
  const fixture = await fakeDockerFixture();
  const command = `. '${helper}'; $id=New-DBPilotOwnedContainer -DockerBinary '${fixture.docker}' -Name 'dbpilot-volume-cleanup-0123456789abcdef0123456789abcdef' -CreateArguments @('postgres:16-alpine'); Remove-DBPilotOwnedContainer -DockerBinary '${fixture.docker}' -ContainerID $id`;
  try {
    const result = pwsh(['-Command', command], { DOCKER_LOG: fixture.log });
    assert.equal(result.status, 0, result.stderr);
    const invocations = await readFile(fixture.log, 'utf8');
    assert.match(invocations, /^rm -f -v created-id$/m);
    assert.doesNotMatch(invocations, /rm .*preexisting-id/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('owned-container helper performs no delete when create fails', async () => {
  const fixture = await fakeDockerFixture();
  const command = `. '${helper}'; $id=$null; try { $id=New-DBPilotOwnedContainer -DockerBinary '${fixture.docker}' -Name 'dbpilot-smoke-0123456789abcdef0123456789abcdef' -CreateArguments @('image') } finally { Remove-DBPilotOwnedContainer -DockerBinary '${fixture.docker}' -ContainerID $id }`;
  try {
    const result = pwsh(['-Command', command], { DOCKER_LOG: fixture.log, DOCKER_MODE: 'create-fails' });
    assert.notEqual(result.status, 0);
    const invocations = await readFile(fixture.log, 'utf8');
    assert.match(invocations, /create --name dbpilot-smoke-/);
    assert.doesNotMatch(invocations, /^rm /m);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('owned-container helper fails on an exact collision without create or delete', async () => {
  const fixture = await fakeDockerFixture();
  const command = `. '${helper}'; $id=$null; try { $id=New-DBPilotOwnedContainer -DockerBinary '${fixture.docker}' -Name 'dbpilot-smoke-0123456789abcdef0123456789abcdef' -CreateArguments @('image') } finally { Remove-DBPilotOwnedContainer -DockerBinary '${fixture.docker}' -ContainerID $id }`;
  try {
    const result = pwsh(['-Command', command], { DOCKER_LOG: fixture.log, DOCKER_MODE: 'collision' });
    assert.notEqual(result.status, 0);
    const invocations = await readFile(fixture.log, 'utf8');
    assert.match(invocations, /^ps /m);
    assert.doesNotMatch(invocations, /^create /m);
    assert.doesNotMatch(invocations, /^rm /m);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('Kylin verifier rejects every image reference except the approved V10 SP1 tag before Docker use', async () => {
  const fixture = await fakeDockerFixture();
  const dummyGo = join(fixture.root, 'go.exe');
  await writeFile(dummyGo, 'not executed');
  try {
    const result = pwsh(['-File', kylinVerifier, '-Image', 'kylin:latest', '-Architecture', 'amd64', '-DockerBinary', fixture.docker, '-GoBinary', dummyGo], { DOCKER_LOG: fixture.log });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /cr\.kylinos\.cn\/kylin\/kylin-server-platform:v10sp1/);
    await assert.rejects(readFile(fixture.log, 'utf8'), { code: 'ENOENT' });
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});
