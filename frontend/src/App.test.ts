import { beforeEach, describe, expect, it, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import { nextTick, reactive } from 'vue';
import App from './App.vue';
import { useAuthStore } from '@/stores/auth';

const appMocks = vi.hoisted(() => ({
  route: {
    name: 'dashboard',
    fullPath: '/',
    meta: { fullScreen: false, requiresAuth: true },
  },
  replace: vi.fn(),
  loadOverrides: vi.fn(),
  websocketStore: null as null | {
    sessionExpired: boolean;
    connect: ReturnType<typeof vi.fn>;
    disconnect: ReturnType<typeof vi.fn>;
  },
}));

vi.mock('vue-router', () => ({
  useRoute: () => appMocks.route,
  useRouter: () => ({ replace: appMocks.replace }),
}));

vi.mock('@/composables/useDeviceOverrides', () => ({
  useDeviceOverrides: () => ({ loadOverrides: appMocks.loadOverrides }),
}));

vi.mock('@/stores/websocket', () => ({
  useWebSocketStore: () => appMocks.websocketStore,
}));

vi.mock('@/api', () => ({
  API_UNAUTHORIZED_EVENT: 'routerview:unauthorized',
  fetchAuthStatus: vi.fn(),
  fetchMe: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
  pair: vi.fn(),
}));

describe('App authenticated lifecycle', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    appMocks.replace.mockReset();
    appMocks.loadOverrides.mockReset();
    appMocks.websocketStore = reactive({
      sessionExpired: false,
      connect: vi.fn(),
      disconnect: vi.fn(),
    });
  });

  it('starts the new session after a pending old startup finishes', async () => {
    let resolveOldStartup!: () => void;
    appMocks.loadOverrides
      .mockImplementationOnce(() => new Promise<void>((resolve) => {
        resolveOldStartup = resolve;
      }))
      .mockResolvedValueOnce(undefined);

    const pinia = createPinia();
    setActivePinia(pinia);
    const auth = useAuthStore();
    auth.user = {
      username: 'admin',
      role: 'admin',
      session_kind: 'standard',
      capabilities: ['read', 'configure'],
    };
    auth.state = 'authenticated';

    mount(App, {
      global: {
        plugins: [pinia],
        stubs: {
          MainLayout: { template: '<main><slot /></main>' },
          RouterView: true,
        },
      },
    });
    await nextTick();
    await flushPromises();
    expect(appMocks.websocketStore?.connect).toHaveBeenCalledOnce();

    auth.state = 'anonymous';
    auth.user = null;
    await nextTick();
    expect(appMocks.websocketStore?.disconnect).toHaveBeenCalledOnce();

    auth.user = {
      username: 'admin',
      role: 'admin',
      session_kind: 'standard',
      capabilities: ['read', 'configure'],
    };
    auth.state = 'authenticated';
    await nextTick();
    expect(appMocks.websocketStore?.connect).toHaveBeenCalledOnce();

    resolveOldStartup();
    await flushPromises();

    expect(appMocks.websocketStore?.connect).toHaveBeenCalledTimes(2);
    expect(appMocks.loadOverrides).toHaveBeenCalledTimes(2);
  });
});
