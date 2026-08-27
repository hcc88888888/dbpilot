import test from 'node:test';
import assert from 'node:assert/strict';
import { renderPermissionSource } from '../../scripts/contracts/generate-permissions.mjs';

function documentWithPermission(permission) {
  const operation = { operationId: 'getJob' };
  if (permission !== undefined) {
    operation['x-dbpilot-permission'] = permission;
  }

  return {
    paths: {
      '/jobs/{job_id}': {
        get: operation,
      },
    },
  };
}

test('permission generation rejects an operation without a permission', () => {
  assert.throws(
    () => renderPermissionSource(documentWithPermission(undefined)),
    /getJob.*exactly one x-dbpilot-permission.*found 0/,
  );
});

test('permission generation rejects an operation with multiple permissions', () => {
  assert.throws(
    () => renderPermissionSource(documentWithPermission(['platform.jobs.read', 'platform.jobs.cancel'])),
    /getJob.*exactly one x-dbpilot-permission.*found 2/,
  );
});

test('permission generation is deterministic', () => {
  const document = {
    paths: {
      '/jobs/{job_id}': {
        get: {
          operationId: 'getJob',
          'x-dbpilot-permission': 'platform.jobs.read',
        },
      },
      '/audit-events': {
        get: {
          operationId: 'listAuditEvents',
          'x-dbpilot-permission': 'platform.audit.read',
        },
      },
    },
  };

  const source = renderPermissionSource(document);
  assert.ok(source.indexOf('PermissionGetJob') < source.indexOf('PermissionListAuditEvents'));
  assert.match(source, /"getJob":\s+PermissionGetJob/);
});
