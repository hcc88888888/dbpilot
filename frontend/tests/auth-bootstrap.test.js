import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';

const APP_URL = new URL('../app.js', import.meta.url);

test('configured bootstrap snapshots one token provider for inspection and reports without exposing its value', async () => {
  const secret = 'eyJ.acceptance-secret.signature';
  const firstProvider = async () => secret;
  const captures = bootstrapCaptures({
    baseUrl: 'https://frontend:8443',
    getAccessToken: firstProvider,
  });

  assert.equal(captures.api.inspection.getAccessToken, firstProvider);
  assert.equal(captures.api.reports.getAccessToken, firstProvider);
  assert.equal(captures.api.inspection.getAccessToken, captures.api.reports.getAccessToken);

  captures.window.DBPILOT_GET_ACCESS_TOKEN = async () => 'replacement-token';
  assert.equal(await captures.api.inspection.getAccessToken(), secret);
  assert.equal(await captures.api.reports.getAccessToken(), secret);

  const exposed = JSON.stringify({
    dom: [...captures.elements.values()].map((element) => element.innerHTML),
    toast: captures.elements.get('#toast').textContent,
    url: captures.window.location.href,
    console: captures.consoleCalls,
  });
  assert.equal(exposed.includes(secret), false);
});

test('configured bootstrap supplies the same no-token provider while demo bootstrap stays local', async () => {
  const configured = bootstrapCaptures({ baseUrl: 'https://frontend:8443' });
  assert.equal(typeof configured.api.inspection.getAccessToken, 'function');
  assert.equal(configured.api.inspection.getAccessToken, configured.api.reports.getAccessToken);
  assert.equal(await configured.api.inspection.getAccessToken(), undefined);

  let demoTokenReads = 0;
  const demo = bootstrapCaptures({
    baseUrl: '',
    getAccessToken: async () => {
      demoTokenReads += 1;
      throw new Error('demo must not request authentication');
    },
  });
  assert.equal(demo.api.inspection.baseUrl, '');
  assert.equal(demo.api.reports.baseUrl, '');
  assert.equal(demoTokenReads, 0);
});

function bootstrapCaptures({ baseUrl, getAccessToken } = {}) {
  const source = readAppSource();
  const elements = new Map();
  const listeners = new Map();
  const api = {};
  const centers = {};
  const consoleCalls = [];
  const element = (selector) => {
    if (elements.has(selector)) return elements.get(selector);
    const value = createElement(selector);
    elements.set(selector, value);
    return value;
  };
  const document = {
    body: { insertAdjacentHTML() {} },
    querySelector: element,
    querySelectorAll: () => [],
    addEventListener(type, callback) { listeners.set(type, callback); },
  };
  const window = {
    DBPILOT_CONTROL_PLANE_URL: baseUrl,
    DBPILOT_ALERT_CONTEXT: {
      tenantId: 'tenant-acceptance',
      projectId: 'project-acceptance',
      permissions: {
        'inspection:view': true,
        'inspection:manage': true,
        'inspection:execute': true,
      },
    },
    DBPILOT_GET_ACCESS_TOKEN: getAccessToken,
    location: { hash: '', href: 'https://frontend:8443/#inspection' },
  };
  const modules = [
    ['Alert', true], ['Monitoring'], ['WorkOrder'], ['Audit'], ['Reports'], ['Inspection'],
    ['SqlWindow'], ['SqlReview'], ['SlowSql'], ['Locks'], ['SchemaDiff'],
  ];
  for (const [name, resolvesContext] of modules) {
    window[`DBPilot${name}Api`] = {
      create(options) {
        api[name.toLowerCase()] = options;
        return {};
      },
    };
    window[`DBPilot${name}Center`] = {
      ...(resolvesContext ? {
        resolveAlertContext(_baseUrl, context) {
          return {
            available: true,
            scope: { tenantId: context.tenantId, projectId: context.projectId },
            permissions: context.permissions,
          };
        },
      } : {}),
      create(options) {
        centers[name.toLowerCase()] = options;
        return { open() {} };
      },
    };
  }
  const context = {
    window,
    document,
    CSS: { escape: String },
    setTimeout: () => 1,
    console: {
      log: (...values) => consoleCalls.push(values),
      warn: (...values) => consoleCalls.push(values),
      error: (...values) => consoleCalls.push(values),
    },
  };
  vm.runInNewContext(source, context, { filename: 'frontend/app.js' });
  listeners.get('DOMContentLoaded')();
  return { api, centers, consoleCalls, elements, window };
}

let cachedAppSource;
function readAppSource() {
  if (cachedAppSource === undefined) {
    throw new Error('app source must be loaded before bootstrapCaptures');
  }
  return cachedAppSource;
}

test.before(async () => {
  cachedAppSource = await readFile(APP_URL, 'utf8');
});

function createElement(selector) {
  const classes = new Set();
  return {
    selector,
    innerHTML: '',
    textContent: '',
    style: {},
    dataset: {},
    classList: {
      add: (...values) => values.forEach((value) => classes.add(value)),
      remove: (...values) => values.forEach((value) => classes.delete(value)),
    },
    querySelector: () => null,
    querySelectorAll: () => [],
  };
}
