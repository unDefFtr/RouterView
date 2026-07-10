import { beforeEach, describe, expect, it, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import { createPinia } from 'pinia';
import type { ConnectionTestResult } from '@/api';
import WizardView from './WizardView.vue';

const mocks = vi.hoisted(() => {
  class TestApiError extends Error {
    constructor(readonly status: number) {
      super(`HTTP ${status}`);
    }
  }
  return {
    ApiError: TestApiError,
    push: vi.fn(),
    testConnection: vi.fn(),
    updateConfig: vi.fn(),
    fetchFullConfig: vi.fn(),
  };
});

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: mocks.push }),
}));

vi.mock('@/api', () => ({
  ApiError: mocks.ApiError,
  testConnection: mocks.testConnection,
  updateConfig: mocks.updateConfig,
  fetchFullConfig: mocks.fetchFullConfig,
}));

describe('WizardView connection verification', () => {
  beforeEach(() => {
    mocks.testConnection.mockReset();
    mocks.updateConfig.mockReset();
    mocks.fetchFullConfig.mockReset();
    mocks.push.mockReset();
    mocks.fetchFullConfig.mockResolvedValue({
      router_host: '192.168.88.1', router_port: 443, router_scheme: 'https',
      router_username: 'admin', accept_invalid_certs: false,
      poll_interval_secs: 3, theme: 'system',
    });
  });

  it('does not accept a successful result for connection fields changed in flight', async () => {
    let resolveFirst!: (result: ConnectionTestResult) => void;
    mocks.testConnection.mockImplementationOnce(() => new Promise((resolve) => {
      resolveFirst = resolve;
    }));
    const wrapper = mount(WizardView, {
      global: {
        plugins: [createPinia()],
        stubs: { FeatherIcon: true },
      },
    });
    await flushPromises();
    await wrapper.get('#wizard-router-password').setValue('router-secret');

    const nextButton = () => wrapper.get('button.btn-primary');
    expect(nextButton().attributes('disabled')).toBeDefined();

    await wrapper.get('button.btn-test').trigger('click');
    const firstSignal = mocks.testConnection.mock.calls[0][1] as AbortSignal;
    await wrapper.get('#wizard-router-host').setValue('192.168.88.2');
    expect(firstSignal.aborted).toBe(true);
    resolveFirst({ success: true, model: 'RB5009', version: '7.20' });
    await flushPromises();

    expect(wrapper.find('.test-result').exists()).toBe(false);
    expect(nextButton().attributes('disabled')).toBeDefined();

    mocks.testConnection.mockResolvedValueOnce({ success: true, model: 'RB5009' });
    await wrapper.get('button.btn-test').trigger('click');
    await flushPromises();

    expect(wrapper.get('.test-result').classes()).toContain('success');
    expect(nextButton().attributes('disabled')).toBeUndefined();

    await wrapper.get('#wizard-router-username').setValue('operator');
    expect(wrapper.find('.test-result').exists()).toBe(false);
    expect(nextButton().attributes('disabled')).toBeDefined();
  });

  it('reloads the whole form after a save conflict and requires a new connection test', async () => {
    mocks.testConnection.mockResolvedValue({ success: true, model: 'RB5009' });
    mocks.updateConfig.mockRejectedValueOnce(new mocks.ApiError(409));
    mocks.fetchFullConfig
      .mockResolvedValueOnce({
        router_host: '192.168.88.1', router_port: 443, router_scheme: 'https',
        router_username: 'admin', accept_invalid_certs: false,
        poll_interval_secs: 3, theme: 'system',
      })
      .mockResolvedValueOnce({
        router_host: '10.0.0.1', router_port: 8443, router_scheme: 'https',
        router_username: 'operator', accept_invalid_certs: true,
        poll_interval_secs: 8, theme: 'dark',
      });
    const wrapper = mount(WizardView, {
      global: {
        plugins: [createPinia()],
        stubs: { FeatherIcon: true },
      },
    });
    await flushPromises();
    await wrapper.get('#wizard-router-password').setValue('router-secret');
    await wrapper.get('button.btn-test').trigger('click');
    await flushPromises();
    await wrapper.get('button.btn-primary').trigger('click');
    await wrapper.get('button.btn-primary').trigger('click');
    await wrapper.get('button.btn-primary').trigger('click');
    await flushPromises();

    expect((wrapper.get('#wizard-router-host').element as HTMLInputElement).value).toBe('10.0.0.1');
    expect((wrapper.get('#wizard-router-username').element as HTMLInputElement).value).toBe('operator');
    expect((wrapper.get('#wizard-router-password').element as HTMLInputElement).value).toBe('');
    expect(wrapper.find('.test-result').exists()).toBe(false);
    expect(wrapper.get('button.btn-primary').attributes('disabled')).toBeDefined();
    expect(wrapper.get('.save-fail').text()).toContain('请重新输入密码并测试连接');
  });

  it('associates labels with its numeric and certificate controls', async () => {
    const wrapper = mount(WizardView, {
      global: {
        plugins: [createPinia()],
        stubs: { FeatherIcon: true },
      },
    });
    await flushPromises();

    for (const input of wrapper.findAll('input[type="number"], input[type="checkbox"]')) {
      const id = input.attributes('id');
      expect(id).toBeTruthy();
      expect(wrapper.find(`label[for="${id}"]`).exists()).toBe(true);
    }
  });
});
