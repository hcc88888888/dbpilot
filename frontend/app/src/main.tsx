import React from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from 'react-router-dom';
import { AuthProvider } from './auth/AuthProvider';
import { createOidcManager } from './auth/oidc';
import { AsyncBoundary } from './components/AsyncBoundary';
import { createAppRouter } from './routing/router';
import './styles/tokens.css';

const root = createRoot(document.getElementById('root')!);

try {
  const manager = createOidcManager({
    authority: import.meta.env.VITE_OIDC_AUTHORITY ?? '',
    clientId: import.meta.env.VITE_OIDC_CLIENT_ID ?? '',
    redirectUri: import.meta.env.VITE_OIDC_REDIRECT_URI ?? `${window.location.origin}/auth/callback`,
    postLogoutRedirectUri: import.meta.env.VITE_OIDC_POST_LOGOUT_REDIRECT_URI ?? window.location.origin,
  });
  const queryClient = new QueryClient();
  root.render(
    <React.StrictMode>
      <QueryClientProvider client={queryClient}>
        <AuthProvider manager={manager} queryCache={queryClient}>
          <RouterProvider router={createAppRouter()} />
        </AuthProvider>
      </QueryClientProvider>
    </React.StrictMode>,
  );
} catch (error) {
  root.render(<AsyncBoundary error={error} />);
}
