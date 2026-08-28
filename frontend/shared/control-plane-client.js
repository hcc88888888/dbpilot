import { Configuration, PlatformApi } from '../generated/api/dist/index.js';

const REQUEST_OPTIONS = Symbol('controlPlaneRequestOptions');

const PROBLEM_MAPPINGS = Object.freeze({
  validation_failed: { kind: 'validation', message: '请求参数或内容不符合要求，请修改后重试' },
  unauthorized: { kind: 'unauthorized', message: '登录状态已失效，请重新登录' },
  forbidden: { kind: 'forbidden', message: '当前账号没有该项目的操作权限' },
  not_found: { kind: 'not-found', message: '请求的对象不存在或已无权访问' },
  conflict: { kind: 'conflict', message: '对象已更新或存在引用冲突，请刷新后重试' },
  precondition_failed: { kind: 'conflict', message: '对象已更新或存在引用冲突，请刷新后重试' },
  unavailable: { kind: 'unavailable', message: '服务暂时不可用，请稍后重试' },
});

const STATUS_MAPPINGS = Object.freeze({
  400: 'validation_failed',
  401: 'unauthorized',
  403: 'forbidden',
  404: 'not_found',
  409: 'conflict',
  412: 'precondition_failed',
  413: 'validation_failed',
  429: 'unavailable',
  500: 'unavailable',
  502: 'unavailable',
  503: 'unavailable',
  504: 'unavailable',
});

const GENERIC_PROBLEM = Object.freeze({
  kind: 'request-failed',
  message: '请求未能完成，请稍后重试',
});

export class ControlPlaneError extends Error {
  constructor({ code, status, requestId, kind, message }) {
    super(message);
    this.name = 'ControlPlaneError';
    this.code = code;
    this.status = status;
    this.requestId = requestId;
    this.kind = kind;
  }
}

export function createControlPlaneClient({
  baseUrl = '',
  getAccessToken = () => undefined,
  fetchImpl = globalThis.fetch,
  requestIdFactory = defaultRequestId,
	traceparentFactory = defaultTraceparent,
} = {}) {
  if (typeof getAccessToken !== 'function') throw new TypeError('getAccessToken must be a function');
  if (typeof fetchImpl !== 'function') throw new TypeError('fetchImpl must be a function');
  if (typeof requestIdFactory !== 'function') throw new TypeError('requestIdFactory must be a function');
	if (typeof traceparentFactory !== 'function') throw new TypeError('traceparentFactory must be a function');

  return {
    forScope({ tenantId, projectId }) {
      const configuration = new Configuration({
        basePath: scopedBaseUrl(baseUrl, tenantId, projectId),
        fetchApi: fetchImpl,
        middleware: [requestMiddleware({ getAccessToken, requestIdFactory, traceparentFactory })],
      });
      const api = new PlatformApi(configuration);

      return {
        platform: controlPlanePlatform(api),
        inspection: controlPlanePlatform(api),
        requestOptions({ idempotencyKey, etag, signal } = {}) {
          return {
            [REQUEST_OPTIONS]: true,
            idempotencyKey,
            ifMatch: etag,
            initOverrides: async ({ init }) => ({
              ...init,
              headers: init.headers,
              ...(signal === undefined ? {} : { signal }),
            }),
          };
        },
      };
    },
  };
}

function controlPlanePlatform(api) {
  return new Proxy(api, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (typeof value !== 'function' || property === 'constructor') return value;

      return async (...args) => {
        const requestOptions = args.at(-1);
        const hasRequestOptions = requestOptions?.[REQUEST_OPTIONS] === true;
        const methodArgs = hasRequestOptions ? args.slice(0, -1) : args;

        if (hasRequestOptions && methodArgs.length > 0 && isRequestParameters(methodArgs[0])) {
          methodArgs[0] = {
            ...methodArgs[0],
            ...(requestOptions.idempotencyKey === undefined ? {} : { idempotencyKey: requestOptions.idempotencyKey }),
            ...(requestOptions.ifMatch === undefined ? {} : { ifMatch: requestOptions.ifMatch }),
          };
        }

        try {
          if (hasRequestOptions) methodArgs.push(requestOptions.initOverrides);
          return await value.apply(target, methodArgs);
        }
        catch (error) {
          if (isAbortError(error)) throw error;
          if (isAbortError(error?.cause)) throw error.cause;
          throw await toControlPlaneError(error);
        }
      };
    },
  });
}

function requestMiddleware({ getAccessToken, requestIdFactory, traceparentFactory }) {
  return {
    async pre({ url, init }) {
      const token = await getAccessToken();
      const requestId = await requestIdFactory();
			const candidate = await traceparentFactory();
			const traceparent = isValidTraceparent(candidate) ? candidate : defaultTraceparent();
      return {
        url,
        init: {
          ...init,
          headers: {
            ...init.headers,
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
            ...(requestId ? { 'X-Request-ID': String(requestId) } : {}),
					traceparent,
          },
        },
      };
    },
    onError({ error }) {
      if (isAbortError(error)) throw error;
      return undefined;
    },
  };
}

async function toControlPlaneError(error) {
  const response = error?.response;
  const problem = response ? await readProblem(response) : undefined;
  const status = problem?.status ?? response?.status;
  const code = problem?.code ?? STATUS_MAPPINGS[status] ?? 'request_failed';
  const mapping = PROBLEM_MAPPINGS[code] ?? PROBLEM_MAPPINGS[STATUS_MAPPINGS[status]] ?? GENERIC_PROBLEM;

  return new ControlPlaneError({
    code,
    status,
    requestId: problem?.request_id,
    kind: mapping.kind,
    message: mapping.message,
  });
}

async function readProblem(response) {
  try {
    const value = await response.json();
    if (value && typeof value === 'object' && typeof value.code === 'string') return value;
  }
  catch {
    // Non-problem error responses use the generic status mapping below.
  }
  return undefined;
}

function scopedBaseUrl(baseUrl, tenantId, projectId) {
  return `${String(baseUrl).replace(/\/+$/, '')}/api/v1/tenants/${encodeURIComponent(String(tenantId))}/projects/${encodeURIComponent(String(projectId))}`;
}

function isRequestParameters(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isAbortError(error) {
  return error?.name === 'AbortError';
}

function defaultRequestId() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  return `req-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function isValidTraceparent(value) {
	if (typeof value !== 'string' || value !== value.trim().toLowerCase()) return false;
	const match = /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/.exec(value);
	return Boolean(match && match[1] !== 'ff' && !/^0+$/.test(match[2]) && !/^0+$/.test(match[3]));
}

function defaultTraceparent() {
	const trace = randomHex(16);
	const parent = randomHex(8);
	return `00-${trace}-${parent}-01`;
}

function randomHex(size) {
	const bytes = new Uint8Array(size);
	if (globalThis.crypto?.getRandomValues) {
		globalThis.crypto.getRandomValues(bytes);
	} else {
		for (let index = 0; index < bytes.length; index += 1) bytes[index] = Math.floor(Math.random() * 256);
	}
	if (bytes.every((value) => value === 0)) bytes[bytes.length - 1] = 1;
	return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}
