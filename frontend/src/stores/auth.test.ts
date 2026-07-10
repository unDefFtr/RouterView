import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import { useAuthStore } from './auth';
import type { AuthUser } from '@/api';

const api = vi.hoisted(() => ({
  fetchAuthStatus: vi.fn(),
  fetchMe: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
  pair: vi.fn(),
}));

vi.mock('@/api', () => ({
  API_UNAUTHORIZED_EVENT: 'routerview:unauthorized',
  ...api,
}));

const admin: AuthUser = {
  username: 'admin',
  role: 'admin' as const,
  session_kind: 'standard',
  capabilities: ['read', 'configure', 'manage_devices', 'manage_sessions'],
};
const viewer: AuthUser = {
  username: 'admin',
  role: 'viewer' as const,
  session_kind: 'fixed',
  capabilities: ['read'],
};

let store: ReturnType<typeof useAuthStore>;

beforeEach(() => {
  setActivePinia(createPinia());
  store = useAuthStore();
});

afterEach(() => store.stopUnauthorizedListener());

describe('auth store', () => {
  it('represents setup-required without requesting a protected identity', async () => {
    api.fetchAuthStatus.mockResolvedValue({ setup_required: true, authenticated: false });
    await store.initialize();
    expect(store.state).toBe('setup_required');
    expect(store.authenticated).toBe(false);
    expect(api.fetchMe).not.toHaveBeenCalled();
  });

  it('loads an authenticated viewer and enforces its capabilities', async () => {
    api.fetchAuthStatus.mockResolvedValue({ setup_required: false, authenticated: true });
    api.fetchMe.mockResolvedValue(viewer);
    await store.initialize();
    expect(store.authenticated).toBe(true);
    expect(store.can('read')).toBe(true);
    expect(store.can('manage_devices')).toBe(false);
    expect(store.isAdmin).toBe(false);
  });

  it('adopts login and pairing responses as the current session', async () => {
    api.login.mockResolvedValue(admin);
    await store.login(' admin ', 'secret');
    expect(api.login).toHaveBeenCalledWith('admin', 'secret');
    expect(store.isAdmin).toBe(true);

    api.pair.mockResolvedValue(viewer);
    await store.pair(' pairing-code ');
    expect(api.pair).toHaveBeenCalledWith('pairing-code');
    expect(store.user?.role).toBe('viewer');
  });

  it('invalidates an active session when the central client reports a 401', () => {
    store.state = 'authenticated';
    store.user = admin;
    store.startUnauthorizedListener();
    window.dispatchEvent(new CustomEvent('routerview:unauthorized'));
    expect(store.state).toBe('anonymous');
    expect(store.user).toBeNull();
    expect(store.lastInvalidation).toBe('http');
  });
});
