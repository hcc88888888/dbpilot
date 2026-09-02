import { readFile, writeFile } from 'node:fs/promises';
import { createHash, sign } from 'node:crypto';
import { gzipSync } from 'node:zlib';

export function buildPluginPackage(binary, privateKey, { version, architecture = 'amd64' }) {
  const binaryPath = 'plugin-package/bin/linux-' + architecture + '/dbpilot-plugin-mysql';
  const binaryDigest = sha256(binary);
  const manifest = canonicalJSON({
    binaries: [{ architecture, operating_system: 'linux', path: binaryPath, sha256: binaryDigest, size_bytes: binary.length }],
    capabilities: ['metrics.collect'],
    database_family: 'mysql',
    database_version_range: '>=8.0.0 <9.0.0',
    files: [{ path: binaryPath, sha256: binaryDigest, size_bytes: binary.length }],
    maximum_agent_protocol_version: 'v1',
    metric_template_schema_version: 1,
    minimum_agent_protocol_version: 'v1',
    plugin_id: 'mysql',
    protocol_version: 'v1',
    publisher_id: 'acceptance-publisher',
    signing_key_id: 'acceptance-key',
    supported_variants: ['mysql'],
    version,
  });
  const entries = [
    { name: 'plugin-package/manifest.json', body: Buffer.from(manifest), mode: 0o400 },
    { name: binaryPath, body: binary, mode: 0o500 },
  ];
  const content = createHash('sha256');
  content.update('dbpilot-plugin-content-v1\n');
  for (const entry of [...entries].sort((left, right) => left.name.localeCompare(right.name))) {
    lengthPrefix(content, entry.name);
    lengthPrefix(content, String(entry.body.length));
    lengthPrefix(content, sha256(entry.body));
  }
  const message = Buffer.from('dbpilot-plugin-signature-v1\nmanifest-sha256:' + sha256(Buffer.from(manifest)) + '\ncontent-sha256:' + content.digest('hex') + '\n');
  entries.push({ name: 'plugin-package/SIGNATURE.ed25519', body: sign(null, message, privateKey), mode: 0o400 });
  return gzipSync(tar(entries), { level: 9, mtime: 0 });
}

function canonicalJSON(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map((key) => goJSONString(key) + ':' + canonicalJSON(value[key])).join(',') + '}';
  return typeof value === 'string' ? goJSONString(value) : JSON.stringify(value);
}

function goJSONString(value) {
  return JSON.stringify(value).replace(/&/g, '\\u0026').replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

function lengthPrefix(hash, value) {
  hash.update(String(Buffer.byteLength(value)) + ':' + value);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function tar(entries) {
  const blocks = [];
  for (const entry of entries) {
    const header = Buffer.alloc(512);
    writeTarText(header, 0, 100, entry.name);
    writeTarOctal(header, 100, 8, entry.mode);
    writeTarOctal(header, 108, 8, 0);
    writeTarOctal(header, 116, 8, 0);
    writeTarOctal(header, 124, 12, entry.body.length);
    writeTarOctal(header, 136, 12, 0);
    header.fill(0x20, 148, 156);
    header[156] = '0'.charCodeAt(0);
    writeTarText(header, 257, 6, 'ustar');
    writeTarText(header, 263, 2, '00');
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    writeTarOctal(header, 148, 8, checksum);
    blocks.push(header, entry.body, Buffer.alloc((512 - entry.body.length % 512) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

function writeTarText(buffer, offset, length, value) {
  buffer.write(value, offset, Math.min(length, Buffer.byteLength(value)), 'utf8');
}

function writeTarOctal(buffer, offset, length, value) {
  const encoded = value.toString(8).padStart(length - 2, '0') + '\0 ';
  buffer.write(encoded, offset, length, 'ascii');
}

if (process.argv[1]?.replace(/\\/g, '/').endsWith('/plugin-package.mjs')) {
  const [binaryPath, keyPath, version, outputPath, architecture = 'amd64'] = process.argv.slice(2);
  if (!binaryPath || !keyPath || !version || !outputPath) process.exit(2);
  const [binary, key] = await Promise.all([readFile(binaryPath), readFile(keyPath)]);
  await writeFile(outputPath, buildPluginPackage(binary, key, { version, architecture }), { mode: 0o600 });
}
