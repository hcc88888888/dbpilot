import React from 'react';
import type { DiscoveryCandidate } from '../../../../generated/api/dist/index.js';
import { Drawer } from '../../components/Drawer';

export function CandidateDetailDrawer({ candidate, onClose }: { candidate?: DiscoveryCandidate; onClose(): void }) {
  return (
    <Drawer open={Boolean(candidate)} title="发现证据" onClose={onClose}>
      {candidate ? <>
        <dl><dt>候选 ID</dt><dd>{candidate.candidateId}</dd><dt>来源</dt><dd>{candidate.discoverySource}</dd><dt>可信度</dt><dd>{Math.round(candidate.confidence * 100)}%</dd><dt>规则版本</dt><dd>{candidate.ruleRevision}</dd><dt>观测版本</dt><dd>{candidate.observationRevision}</dd></dl>
        {candidate.possibleDuplicateOf ? <p className="notice notice--warning">可能与 {candidate.possibleDuplicateOf} 重复，请核对后再纳管。</p> : null}
        <h3>脱敏证据</h3>
        <ul className="evidence-list">{[...candidate.evidenceSummary].map((evidence, index) => <li key={`${evidence.kind}-${index}`}><strong>{evidence.kind}</strong><span>{evidence.value}</span></li>)}</ul>
        <p className="muted">仅展示服务端允许的脱敏证据，不展示完整命令行或环境变量。</p>
      </> : null}
    </Drawer>
  );
}
