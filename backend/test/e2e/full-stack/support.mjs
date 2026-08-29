import { createHash } from 'node:crypto';

const SCREENSHOT_MARKUP = '<main><h1>DBPilot acceptance failed</h1><p>Sanitized diagnostics are attached.</p></main>';
const SENSITIVE_EVIDENCE = /(?:authorization|bearer\s+\S+|password|private key|postgres:\/\/|credential|access[_ -]?token)/i;

export function browserPhaseState({ tenantID, projectID, onlineAgentID, offlineAgentID, policy, run, report } = {}) {
  const commands = Array.isArray(report?.references?.commands) ? report.references.commands : [];
  const onlineCommand = commands.find((command) => command?.target_id === onlineAgentID)?.command_id;
  const offlineCommand = commands.find((command) => command?.target_id === offlineAgentID)?.command_id;
  const state = {
    version: 1,
    tenant_id: tenantID,
    project_id: projectID,
    online_agent_id: onlineAgentID,
    offline_agent_id: offlineAgentID,
    policy_id: policy?.id,
    run_id: run?.id,
    job_id: report?.references?.job_id,
    report_id: report?.id,
    online_command_id: onlineCommand,
    offline_command_id: offlineCommand,
    journal_command_id: onlineCommand,
    audit_correlation: report?.references?.audit_correlation,
  };
  if (report?.id !== run?.report_id || onlineCommand === offlineCommand || Object.entries(state).some(([name, value]) => (
    name !== 'version' && (typeof value !== 'string' || !value || value !== value.trim() || /[\r\n\t]/.test(value))
  ))) throw new Error('browser phase state is invalid');
  return Object.freeze(state);
}

export function assertNoSecretExposure({ secrets = [], body = '', url = '', consoleEntries = [] } = {}) {
  const retained = [body, url, ...consoleEntries].map(String);
  if (normalizedSecrets(secrets).some((secret) => retained.some((value) => value.includes(secret)))) {
    throw new Error('browser secret exposure detected');
  }
}

export function createFailureArtifacts({ secrets = [], html = '', consoleEntries = [] } = {}) {
  return {
    dom: redactSecrets(html, secrets),
    console: consoleEntries.map((entry) => redactSecrets(entry, secrets)).join('\n'),
    screenshotMarkup: SCREENSHOT_MARKUP,
  };
}

export function redactSecrets(value, secrets = []) {
  let redacted = String(value ?? '');
  for (const secret of normalizedSecrets(secrets)) redacted = redacted.replaceAll(secret, '[REDACTED]');
  return redacted.replace(/Bearer\s+[^\s<"']+/gi, 'Bearer [REDACTED]');
}

export function findingEvidenceIsComplete(finding) {
  if (!finding || typeof finding !== 'object') return false;
  const evidenceValues = findingEvidenceValues(finding);
  const summary = String(finding.summary ?? '').trim();
  const recommendation = String(finding.recommendation ?? '').trim();
  const hasWarning = finding.warning_threshold !== undefined && finding.warning_threshold !== null;
  const hasCritical = finding.critical_threshold !== undefined && finding.critical_threshold !== null;
  const thresholdsValid = hasWarning === hasCritical && (!hasWarning || (Number.isFinite(finding.warning_threshold) && Number.isFinite(finding.critical_threshold)));
  const bounded = JSON.stringify({ evidenceValues, summary, recommendation }).length <= 80_000;
  return evidenceValues.length > 0
    && summary.length > 0
    && recommendation.length > 0
    && thresholdsValid
    && bounded
    && !SENSITIVE_EVIDENCE.test(JSON.stringify({ evidenceValues, summary, recommendation }));
}

export function findingEvidenceValues(finding) {
  const values = [];
  const fields = finding?.evidence_fields;
  if (fields && typeof fields === 'object' && !Array.isArray(fields)) {
    values.push(...Object.values(fields));
  }
  const evidence = finding?.evidence;
  if (typeof evidence === 'string' && evidence.trim()) {
    try {
      const parsed = JSON.parse(evidence);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) values.push(...Object.values(parsed));
      else values.push(evidence);
    } catch {
      values.push(evidence);
    }
  }
  return [...new Set(values.map((value) => String(value ?? '').trim()).filter(Boolean))];
}

export function renderedFindingMatches(renderedText, finding) {
  if (!findingEvidenceIsComplete(finding)) return false;
  const text = String(renderedText ?? '');
  const expected = [String(finding.summary).trim(), String(finding.recommendation).trim(), ...findingEvidenceValues(finding)];
  if (finding.warning_threshold !== undefined && finding.warning_threshold !== null) expected.push(String(finding.warning_threshold));
  if (finding.critical_threshold !== undefined && finding.critical_threshold !== null) expected.push(String(finding.critical_threshold));
  return expected.every((value) => text.includes(value));
}

export function verifyArtifactDownload({ format, bytes, responseContentType, metadata, runId } = {}) {
  const expectedType = format === 'html' ? 'text/html; charset=utf-8' : format === 'json' ? 'application/json' : '';
  if (!expectedType || canonicalContentType(metadata?.content_type) !== expectedType) throw new Error('artifact download format mismatch');
  if (canonicalContentType(responseContentType) !== expectedType) throw new Error('artifact download content type mismatch');
  const contents = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes ?? []);
  if (!Number.isSafeInteger(metadata?.size_bytes) || contents.length !== metadata.size_bytes) throw new Error('artifact download size mismatch');
  const checksum = String(metadata?.checksum ?? '');
  const calculated = `sha256:${createHash('sha256').update(contents).digest('hex')}`;
  if (!/^sha256:[a-f0-9]{64}$/.test(checksum) || calculated !== checksum) throw new Error('artifact download checksum mismatch');
  if (!downloadContainsRun(format, contents, runId)) throw new Error('artifact download run mismatch');
}

function downloadContainsRun(format, contents, runId) {
  const expected = String(runId ?? '');
  if (!expected) return false;
  if (format === 'html') return contents.includes(Buffer.from(expected, 'utf8'));
  try {
    return JSON.parse(contents.toString('utf8'))?.run_id === expected;
  } catch {
    return false;
  }
}

function canonicalContentType(value) {
  return String(value ?? '').trim().toLowerCase().replace(/;\s*charset\s*=\s*/g, '; charset=');
}

function normalizedSecrets(secrets) {
  return [...new Set(secrets.map((secret) => String(secret ?? '')).filter(Boolean))];
}
