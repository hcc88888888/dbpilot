import { InMemoryWebStorage, UserManager, WebStorageStateStore, type UserManagerSettings } from 'oidc-client-ts';

export type OidcEnvironment = {
  authority: string;
  clientId: string;
  redirectUri: string;
  postLogoutRedirectUri?: string;
};

export function createOidcSettings(environment: OidcEnvironment): UserManagerSettings {
  for (const [name, value] of Object.entries(environment)) {
    if (name !== 'postLogoutRedirectUri' && !value.trim()) {
      throw new Error(`Missing OIDC configuration: ${name}`);
    }
  }

  return {
    authority: environment.authority,
    client_id: environment.clientId,
    redirect_uri: environment.redirectUri,
    post_logout_redirect_uri: environment.postLogoutRedirectUri,
    response_type: 'code',
    response_mode: 'query',
    scope: 'openid profile',
    automaticSilentRenew: true,
    monitorSession: false,
    stateStore: new WebStorageStateStore({ store: sessionStorage }),
    userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
  };
}

export function createOidcManager(environment: OidcEnvironment): UserManager {
  return new UserManager(createOidcSettings(environment));
}
