import { createAppRouter } from './router';

type SigninCallbackManager = {
  signinCallback(url?: string): Promise<unknown | undefined>;
};

type RouterFactory = typeof createAppRouter;

export type RouterBootstrapResult =
  | { kind: 'application'; router: ReturnType<RouterFactory> }
  | { kind: 'callback-only' };

function isSigninCallback(url: URL): boolean {
  return url.searchParams.has('state') && (url.searchParams.has('code') || url.searchParams.has('error'));
}

export async function createRouterAfterSigninCallback(
  manager: SigninCallbackManager,
  routerFactory: RouterFactory = createAppRouter,
): Promise<RouterBootstrapResult> {
  const callbackUrl = new URL(window.location.href);
  if (isSigninCallback(callbackUrl)) {
    const user = await manager.signinCallback(callbackUrl.href);
    if (!user) return { kind: 'callback-only' };
    window.history.replaceState({}, document.title, '/');
  }
  return { kind: 'application', router: routerFactory() };
}
