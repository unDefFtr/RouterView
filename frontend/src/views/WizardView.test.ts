import { beforeEach, describe, expect, it, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import { createPinia } from 'pinia';
import type { ConnectionTestResult } from '@/api';
import WizardView from './WizardView.vue';

const mocks = vi.hoisted(() => ({
  push: vi.fn(),
  testConnection: vi.fn(),
  updateConfig: vi.fn(),
}));

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: mocks.push }),
}));

vi.mock('@/api', () => ({
  testConnection: mocks.testConnection,
  updateConfig: mocks.updateConfig,
}));

describe('WizardView connection verification', () => {
  beforeEach(() => {
    mocks.testConnection.mockReset();
    mocks.updateConfig.mockReset();
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

    const nextButton = () => wrapper.get('button.btn-primary');
    expect(nextButton().attributes('disabled')).toBeDefined();

    await wrapper.get('button.btn-test').trigger('click');
    await wrapper.get('#wizard-router-host').setValue('192.168.88.2');
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
});
