import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, copyFile, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
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

test('breaking check invokes Buf when origin/main contains the canonical contract', async () => {
  const root = await createBreakingFixture({ includeOriginMain: true, includeCanonicalContract: true });
  const binDirectory = join(root, 'bin');
  const invocationLog = join(root, 'buf-invocation.txt');
  await mkdir(binDirectory);
  if (process.platform === 'win32') {
    await writeFile(join(binDirectory, 'buf.cmd'), '@echo off\r\necho %* > "%BUF_LOG%"\r\n');
  } else {
    const fakeBuf = join(binDirectory, 'buf');
    await writeFile(fakeBuf, '#!/bin/sh\nprintf "%s " "$@" > "$BUF_LOG"\n');
    await chmod(fakeBuf, 0o755);
  }

  try {
    const result = runBreaking(root, {
      BUF_LOG: invocationLog,
      PATH: `${binDirectory};${process.env.PATH}`,
    });
    assert.equal(result.status, 0, result.stderr);
    const invocation = await readFile(invocationLog, 'utf8');
    assert.match(invocation, /^breaking /);
    assert.match(invocation, /\.git#branch=origin\/main/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
