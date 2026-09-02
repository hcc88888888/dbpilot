import type { AuthManager, AuthUser } from './AuthProvider';

type AcceptanceGlobal = typeof globalThis & { __DBPilotAcceptanceTokenProvider?: () => Promise<string | undefined> };

export function createAcceptanceAuthManager(): AuthManager & { signinCallback(url?: string): Promise<AuthUser | null> } {
  const provider = (globalThis as AcceptanceGlobal).__DBPilotAcceptanceTokenProvider;
  if (typeof provider !== 'function') throw new Error('Acceptance token provider is unavailable');
  const user = async (): Promise<AuthUser | null> => {
    const accessToken = await provider();
    if (!accessToken) return null;
    const encoded = accessToken.split('.')[1];
    if (!encoded) throw new Error('Acceptance token is invalid');
    const base64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
    const profile = JSON.parse(atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='))) as Record<string, unknown>;
    return { access_token: accessToken, expired: false, profile };
  };
  return {
    getUser: user,
    signinCallback: user,
    signinRedirect: async () => undefined,
    signoutRedirect: async () => undefined,
    events: {
      addUserLoaded: () => undefined, removeUserLoaded: () => undefined,
      addUserUnloaded: () => undefined, removeUserUnloaded: () => undefined,
      addSilentRenewError: () => undefined, removeSilentRenewError: () => undefined,
    },
  };
}
