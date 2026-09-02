import { describe, expect, it } from 'vitest';
import { retryScopedRequest } from '../api/client';
import { discoveryKeys } from './discovery/queries';
import { hostKeys } from './hosts/queries';
import { instanceKeys } from './instances/queries';

const scope = { tenantId: 'tenant-a', projectId: 'project-b' };

describe('project-scoped management query keys', () => {
  it('isolates every list by tenant, project and complete resource filters', () => {
    expect(hostKeys.list(scope, { status: 'stale' })).toEqual(['hosts', 'tenant-a', 'project-b', 'list', { status: 'stale' }]);
    expect(discoveryKeys.list(scope, { source: 'docker', status: 'awaiting_confirmation', databaseFamily: 'mysql' })).toEqual([
      'discovery', 'tenant-a', 'project-b', 'list', { source: 'docker', status: 'awaiting_confirmation', databaseFamily: 'mysql' },
    ]);
    expect(instanceKeys.list(scope, { hostId: 'host-1', databaseFamily: 'mysql', status: 'monitoring' })).toEqual([
      'instances', 'tenant-a', 'project-b', 'list', { hostId: 'host-1', databaseFamily: 'mysql', status: 'monitoring' },
    ]);
  });

  it('retries only transport, throttling, timeout and server failures', () => {
    expect(retryScopedRequest(0, Object.assign(new Error('forbidden'), { response: new Response(null, { status: 403 }) }))).toBe(false);
    expect(retryScopedRequest(0, Object.assign(new Error('busy'), { response: new Response(null, { status: 503 }) }))).toBe(true);
    expect(retryScopedRequest(0, new TypeError('network failed'))).toBe(true);
    expect(retryScopedRequest(1, new TypeError('network failed'))).toBe(false);
  });
});
