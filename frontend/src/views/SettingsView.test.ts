import { beforeEach, describe, expect, it, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import { nextTick } from 'vue';
import SettingsView from './SettingsView.vue';
import { useDashboardStore } from '@/stores/dashboard';

const apiMocks = vi.hoisted(() => ({
  fetchFullConfig: vi.fn(),
  fetchHealth: vi.fn(),
  updateConfig: vi.fn(),
  testConnection: vi.fn(),
  fetchProbeTargets: vi.fn(),
  updateProbeTargets: vi.fn(),
  resetProbeTargets: vi.fn(),
}));

vi.mock('@/api', () => apiMocks);

describe('SettingsView', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    apiMocks.fetchHealth.mockResolvedValue({ status: 'ok', version: '0.2.0' });
    apiMocks.fetchFullConfig.mockResolvedValue({
      routeros_host: '192.168.88.1',
      routeros_port: 443,
      routeros_scheme: 'https',
      routeros_username: 'admin',
      routeros_password: '',
      accept_invalid_certs: false,
      poll_interval_secs: 5,
      probe_interval_secs: 60,
      db_raw_retention_days: 7,
      db_total_retention_days: 90,
      latency_good_ms: 30,
      latency_poor_ms: 100,
      theme: 'system',
      routeros_configured: true,
      wizard_completed: true,
    });
  });

  it('shows the actual health contract and reacts to router connection changes', async () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    const dashboard = useDashboardStore();
    const wrapper = mount(SettingsView, {
      global: {
        plugins: [pinia],
        stubs: {
          FeatherIcon: true,
          ProbeTargetEditor: true,
        },
      },
    });
    await flushPromises();

    const statuses = wrapper.findAll('.status-item');
    expect(statuses[0].text()).toContain('未连接');
    expect(statuses[1].text()).toContain('ok');
    expect(statuses[2].text()).toContain('0.2.0');

    dashboard.routerosConnected = true;
    await nextTick();

    expect(statuses[0].text()).toContain('已连接');
  });
});
