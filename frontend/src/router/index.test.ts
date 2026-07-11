import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import type { RouteLocationNormalized } from 'vue-router';
import { authNavigationGuard } from './index';
import { useAuthStore } from '@/stores/auth';

const api = vi.hoisted(() => ({
  fetchFullConfig: vi.fn(), fetchAuthStatus: vi.fn(), fetchMe: vi.fn(),
  login: vi.fn(), logout: vi.fn(), pair: vi.fn(),
}));

vi.mock('@/api', () => ({ API_UNAUTHORIZED_EVENT: 'routerview:unauthorized', ...api }));

function route(name: string, meta: Record<string, unknown> = {}): RouteLocationNormalized {
  return { name, meta, fullPath: `/${name}` } as unknown as RouteLocationNormalized;
}

beforeEach(() => setActivePinia(createPinia()));

describe('authentication navigation guard', () => {
  it('sends setup-required installations only to the setup instructions', async () => {
    const auth = useAuthStore();
    auth.state = 'setup_required';
    expect(await authNavigationGuard(route('dashboard', { requiresAuth: true })))
      .toEqual({ name: 'setup-required' });
  });

  it('preserves the protected destination for anonymous users', async () => {
    const auth = useAuthStore();
    auth.state = 'anonymous';
    expect(await authNavigationGuard(route('devices', { requiresAuth: true })))
      .toEqual({ name: 'login', query: { redirect: '/devices' } });
  });

  it('prevents a viewer from opening administrator routes', async () => {
    const auth = useAuthStore();
    auth.state = 'authenticated';
    auth.user = {
      username: 'admin', display_name: 'Wall display', role: 'viewer',
      session_kind: 'fixed', auth_method: 'pairing', provider_name: null,
      capabilities: ['read'],
    };
    expect(await authNavigationGuard(route('settings', {
      requiresAuth: true, capability: 'configure',
    }))).toEqual({ name: 'dashboard' });
  });

  it('lets only the OIDC completion route initialize its own callback state', async () => {
    const auth = useAuthStore();
    expect(auth.state).toBe('unknown');

    expect(await authNavigationGuard(route('oidc-complete', { oidcCompletion: true }))).toBe(true);
    expect(api.fetchAuthStatus).not.toHaveBeenCalled();
    expect(auth.state).toBe('unknown');
  });
});
