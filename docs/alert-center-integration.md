# Alert center browser bootstrap

When `window.DBPILOT_CONTROL_PLANE_URL` is a non-empty string, the authenticated
application shell must publish the current project context before `DOMContentLoaded`:

```js
window.DBPILOT_ALERT_CONTEXT = {
  authenticated: true,
  tenantId: 'tenant-a',
  projectId: 'project-a',
  permissions: { manage: false },
};
```

`tenantId` and `projectId` must be non-empty strings. `permissions.manage` is
granted only when its value is exactly `true`; a missing or malformed permission
is read-only. A missing, unauthenticated, or malformed context disables HTTP
alert requests and renders the alert center unavailable instead of guessing a
tenant or project.

When no control-plane URL is configured, the frontend intentionally uses the
local `demo / production` scope and demo adapter. Demo scope is never used as a
fallback for a configured HTTP control plane.
