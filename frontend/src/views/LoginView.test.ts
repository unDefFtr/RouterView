import { beforeEach, describe, expect, it, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import LoginView from './LoginView.vue';

const mocks = vi.hoisted(() => {
  class TestApiError extends Error {
    constructor(readonly status: number) {
      super(`HTTP ${status}`);
    }
  }
  return {
    ApiError: TestApiError,
    replace: vi.fn(),
    fetchFullConfig: vi.fn(),
    fetchAuthStatus: vi.fn(),
    fetchMe: vi.fn(),
    login: vi.fn(),
    logout: vi.fn(),
    pair: vi.fn(),
  };
});

vi.mock('vue-router', () => ({
  useRoute: () => ({ query: { redirect: '/traffic' } }),
  useRouter: () => ({ replace: mocks.replace }),
}));

vi.mock('@/api', () => ({
  API_UNAUTHORIZED_EVENT: 'routerview:unauthorized',
  ...mocks,
}));

describe('LoginView', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    mocks.replace.mockReset();
    mocks.login.mockReset();
    mocks.fetchFullConfig.mockReset();
  });

  it('navigates after authentication without turning a configuration failure into a login error', async () => {
    mocks.login.mockResolvedValue({
      username: 'admin',
      role: 'admin',
      session_kind: 'standard',
      capabilities: ['read', 'configure', 'manage_devices', 'manage_sessions'],
    });
    mocks.fetchFullConfig.mockRejectedValue(new Error('configuration unavailable'));
    const pinia = createPinia();
    setActivePinia(pinia);
    const wrapper = mount(LoginView, {
      global: {
        plugins: [pinia],
        stubs: { AuthShell: false, FeatherIcon: true, RouterLink: true },
      },
    });

    await wrapper.get('#login-password').setValue('secret');
    await wrapper.get('form').trigger('submit');
    await flushPromises();

    expect(mocks.login).toHaveBeenCalledWith('admin', 'secret');
    expect(mocks.fetchFullConfig).not.toHaveBeenCalled();
    expect(mocks.replace).toHaveBeenCalledWith('/traffic');
    expect(wrapper.find('[role="alert"]').exists()).toBe(false);
  });
});
