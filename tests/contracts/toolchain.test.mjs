import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { chmod, copyFile, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const breakingScript = join(repoRoot, 'scripts', 'contracts', 'breaking.ps1');
const canonicalAgentContract = 'contracts/protobuf/dbpilot/agent/v1/command.proto';

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    ...options,
  });

  if (result.error) {
    throw result.error;
  }

  return result;
}

async function createBreakingFixture({ includeOriginMain, includeCanonicalContract }) {
  const root = await mkdtemp(join(tmpdir(), 'dbpilot-contract-breaking-'));
  const scriptDirectory = join(root, 'scripts', 'contracts');
  await mkdir(scriptDirectory, { recursive: true });
  await copyFile(breakingScript, join(scriptDirectory, 'breaking.ps1'));
  await writeFile(join(root, 'buf.yaml'), 'version: v2\n');

  if (includeCanonicalContract) {
    const contractPath = join(root, canonicalAgentContract);
    await mkdir(dirname(contractPath), { recursive: true });
    await writeFile(contractPath, 'syntax = "proto3";\npackage dbpilot.agent.v1;\n');
  }

  run('git', ['init'], { cwd: root });
  run('git', ['config', 'user.email', 'contract-test@example.com'], { cwd: root });
  run('git', ['config', 'user.name', 'Contract Test'], { cwd: root });
  run('git', ['add', '.'], { cwd: root });
  run('git', ['commit', '-m', 'baseline'], { cwd: root });

  if (includeOriginMain) {
    run('git', ['update-ref', 'refs/remotes/origin/main', 'HEAD'], { cwd: root });
  }

  return root;
}

function runBreaking(root, env = {}) {
  return run('pwsh', ['-NoProfile', '-File', 'scripts/contracts/breaking.ps1'], {
    cwd: root,
    env: { ...process.env, ...env },
  });
}

test('contract toolchain is pinned and generated output is tracked', async () => {
  const pkg = JSON.parse(await readFile('package.json', 'utf8'));
  assert.equal(pkg.scripts['contracts:lint'], 'pwsh -NoProfile -File scripts/contracts/lint.ps1');
  assert.equal(pkg.scripts['contracts:generate'], 'pwsh -NoProfile -File scripts/contracts/generate.ps1');
  assert.equal(pkg.scripts['contracts:breaking'], 'pwsh -NoProfile -File scripts/contracts/breaking.ps1');
  assert.equal(pkg.devDependencies['@redocly/cli'], '2.2.0');
  assert.equal(pkg.devDependencies['@stoplight/prism-cli'], '5.14.2');
  assert.equal(pkg.devDependencies.typescript, '5.9.2');
  const ignore = await readFile('.gitignore', 'utf8');
  assert.doesNotMatch(ignore, /^backend\/gen\/$/m);
});

test('breaking check fails when origin/main is unavailable', async () => {
  const root = await createBreakingFixture({ includeOriginMain: false, includeCanonicalContract: false });

  try {
    const result = runBreaking(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /origin\/main/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('breaking check accepts an available origin/main without the canonical contract', async () => {
  const root = await createBreakingFixture({ includeOriginMain: true, includeCanonicalContract: false });

  try {
    const result = runBreaking(root);
    assert.equal(result.status, 0, result.stderr);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('breaking check invokes the pinned Buf container when origin/main contains the canonical contract', async () => {
  const root = await createBreakingFixture({ includeOriginMain: true, includeCanonicalContract: true });
  const binDirectory = join(root, 'bin');
  const invocationLog = join(root, 'docker-invocation.txt');
  await mkdir(binDirectory);
  if (process.platform === 'win32') {
    await writeFile(join(binDirectory, 'docker.cmd'), '@echo off\r\necho %* > "%DOCKER_LOG%"\r\n');
  } else {
    const fakeDocker = join(binDirectory, 'docker');
    await writeFile(fakeDocker, '#!/bin/sh\nprintf "%s " "$@" > "$DOCKER_LOG"\n');
    await chmod(fakeDocker, 0o755);
  }

  try {
    const result = runBreaking(root, {
      DOCKER_LOG: invocationLog,
      PATH: `${binDirectory}${delimiter}${process.env.PATH}`,
    });
    assert.equal(result.status, 0, result.stderr);
    const invocation = await readFile(invocationLog, 'utf8');
    assert.match(invocation, /^run --rm /);
    assert.match(invocation, /bufbuild\/buf:1\.57\.2 breaking \/workspace/);
    assert.match(invocation, /--against \/baseline/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('Prism launcher works without curl and cleans its Compose project', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dbpilot-prism-launcher-'));
  const binDirectory = join(root, 'bin');
  const dockerLog = join(root, 'docker-invocations.txt');
  await mkdir(binDirectory);
  if (process.platform === 'win32') {
    await writeFile(join(binDirectory, 'docker.cmd'), '@echo off\r\necho %* >> "%DOCKER_LOG%"\r\n');
  } else {
    const fakeDocker = join(binDirectory, 'docker');
    await writeFile(fakeDocker, '#!/bin/sh\nprintf "%s " "$@" >> "$DOCKER_LOG"\nprintf "\\n" >> "$DOCKER_LOG"\n');
    await chmod(fakeDocker, 0o755);
  }

  const body = await readFile(join(repoRoot, 'contracts', 'examples', 'platform', 'capabilities.json'));
  const server = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(body);
  });
  await new Promise((resolve) => server.listen(4010, resolve));

  try {
    const psHome = run('pwsh', ['-NoProfile', '-Command', '$PSHOME']).stdout.trim();
    const minimalPath = [binDirectory, dirname(process.execPath), psHome].join(delimiter);
    const child = spawn('pwsh', ['-NoProfile', '-File', 'scripts/contracts/start-mock.ps1', '-Test'], {
      cwd: repoRoot,
      env: { ...process.env, DOCKER_LOG: dockerLog, PATH: minimalPath },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const [code] = await new Promise((resolve) => child.on('close', (...args) => resolve(args)));
    assert.equal(code, 0, `${stdout}\n${stderr}`);
    const invocations = await readFile(dockerLog, 'utf8');
    const project = invocations.match(/compose -p (dbpilot-contracts-[0-9]+-[a-f0-9]{32}) /)?.[1];
    assert.ok(project, invocations);
    assert.match(invocations, new RegExp(`compose -p ${project} .* up -d`));
    assert.match(invocations, new RegExp(`compose -p ${project} .* down --volumes --remove-orphans`));
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});
