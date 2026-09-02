import React from 'react';
import type { AcceptDiscoveryCandidateRequest, DiscoveryCandidate, ManagedDatabaseInstance } from '../../../../generated/api/dist/index.js';
import { Drawer } from '../../components/Drawer';
import { FormField } from '../../components/FormField';

const stepTitles = ['确认候选', '确认连接端点', '确认数据库变体', '配置引用', '复核并提交'] as const;

export function AcceptCandidateWizard({
  candidate,
  pending,
  result,
  onClose,
  onSubmit,
}: {
  candidate?: DiscoveryCandidate;
  pending: boolean;
  result?: ManagedDatabaseInstance;
  onClose(): void;
  onSubmit(request: AcceptDiscoveryCandidateRequest): void;
}) {
  const [step, setStep] = React.useState(0);
  const [displayName, setDisplayName] = React.useState('');
  const [endpoint, setEndpoint] = React.useState('');
  const [variant, setVariant] = React.useState('');
  const [credentialRef, setCredentialRef] = React.useState('');
  const [tlsRef, setTlsRef] = React.useState('');

  React.useEffect(() => {
    if (!candidate) return;
    setStep(0);
    setDisplayName(`${candidate.databaseFamily} @ ${candidate.hostId}`);
    setEndpoint(candidate.normalizedEndpoint ?? '');
    setVariant(candidate.databaseVariant);
    setCredentialRef('');
    setTlsRef('');
  }, [candidate]);

  if (!candidate) return null;
  const validSecretRef = (value: string) => /^secret:\/\/\S+$/.test(value);
  const canContinue = step === 0
    ? Boolean(displayName.trim())
    : step === 1
      ? Boolean(endpoint.trim() || candidate.unixSocket)
      : step === 2
        ? Boolean(variant.trim())
        : step === 3
          ? validSecretRef(credentialRef) && (!tlsRef || validSecretRef(tlsRef))
          : true;
  return (
    <Drawer open title="纳管数据库实例" onClose={onClose}>
      <nav aria-label="纳管步骤" className="wizard-steps">{stepTitles.map((title, index) => <span key={title} aria-current={step === index ? 'step' : undefined}>{index + 1}. {title}</span>)}</nav>
      <h2>{stepTitles[step]}</h2>
      {step === 0 ? <div><p>候选 {candidate.candidateId}</p><p>{candidate.databaseFamily} · {candidate.discoverySource} · 可信度 {Math.round(candidate.confidence * 100)}%</p>{candidate.possibleDuplicateOf ? <p className="notice notice--warning">可能与 {candidate.possibleDuplicateOf} 重复。</p> : null}<FormField required label="实例名称" name="accept-display-name" value={displayName} onChange={(event) => setDisplayName(event.target.value)} /></div> : null}
      {step === 1 ? <FormField label="连接端点" name="accept-endpoint" value={endpoint} onChange={(event) => setEndpoint(event.target.value)} hint="仅填写数据库监听地址；不会展示发现命令行。" /> : null}
      {step === 2 ? <FormField label="数据库变体" name="accept-variant" value={variant} onChange={(event) => setVariant(event.target.value)} /> : null}
      {step === 3 ? <div className="form-stack"><FormField required pattern="secret://\\S+" label="凭据引用" name="accept-credential-ref" value={credentialRef} onChange={(event) => setCredentialRef(event.target.value)} hint="填写 secret:// 引用，不填写密码。" /><FormField pattern="secret://\\S+" label="TLS 引用" name="accept-tls-ref" value={tlsRef} onChange={(event) => setTlsRef(event.target.value)} hint="可选，仅填写 secret:// 证书引用。" /></div> : null}
      {step === 4 ? <div className="review-card"><dl><dt>实例名称</dt><dd>{displayName}</dd><dt>连接端点</dt><dd>{endpoint || candidate.unixSocket}</dd><dt>数据库</dt><dd>{candidate.databaseFamily} / {variant}</dd><dt>凭据引用</dt><dd>{credentialRef}</dd><dt>TLS 引用</dt><dd>{tlsRef || '未配置'}</dd></dl>{result ? <p role="status">纳管状态：<strong>{result.managementStatus}</strong></p> : null}</div> : null}
      <footer className="wizard-actions">
        {step > 0 && !result ? <button type="button" onClick={() => setStep((value) => value - 1)}>上一步</button> : null}
        {step < 4 ? <button type="button" disabled={!canContinue} onClick={() => setStep((value) => value + 1)}>下一步</button> : null}
        {step === 4 && !result ? <button type="button" disabled={pending} onClick={() => onSubmit({ displayName, databaseFamily: candidate.databaseFamily, databaseVariant: variant, normalizedEndpoint: endpoint || undefined, unixSocket: endpoint ? undefined : candidate.unixSocket, credentialRef, tlsRef: tlsRef || undefined })}>{pending ? '正在提交…' : '开始纳管'}</button> : null}
      </footer>
    </Drawer>
  );
}
