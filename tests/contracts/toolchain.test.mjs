import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('contract toolchain is pinned and generated output is tracked', async () => {
  const pkg = JSON.parse(await readFile('package.json', 'utf8'));
  assert.equal(pkg.scripts['contracts:lint'], 'powershell -NoProfile -File scripts/contracts/lint.ps1');
  assert.equal(pkg.scripts['contracts:generate'], 'powershell -NoProfile -File scripts/contracts/generate.ps1');
  assert.equal(pkg.scripts['contracts:breaking'], 'powershell -NoProfile -File scripts/contracts/breaking.ps1');
  assert.equal(pkg.devDependencies['@redocly/cli'], '2.2.0');
  assert.equal(pkg.devDependencies['@stoplight/prism-cli'], '5.14.2');
  assert.equal(pkg.devDependencies.typescript, '5.9.2');
  const ignore = await readFile('.gitignore', 'utf8');
  assert.doesNotMatch(ignore, /^backend\/gen\/$/m);
});
