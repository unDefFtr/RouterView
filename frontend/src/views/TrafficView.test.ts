import { beforeEach, describe, expect, it, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import TrafficView from './TrafficView.vue';
import type { TrafficHistoryResponse } from '@/api/index';

const apiMocks = vi.hoisted(() => ({
  fetchTrafficHistory: vi.fn(),
}));

vi.mock('@/api/index', async (importOriginal) => ({
  ...await importOriginal<typeof import('@/api/index')>(),
  fetchTrafficHistory: apiMocks.fetchTrafficHistory,
}));

vi.mock('@/composables/useECharts', async () => {
  const { ref } = await import('vue');
  return {
    useECharts: () => ({
      chartRef: ref<HTMLElement | null>(null),
      initChart: vi.fn(),
      updateOption: vi.fn(),
      hasInstance: vi.fn(() => false),
    }),
  };
});

vi.mock('@/composables/useEChartsDataZoom', () => ({
  useEChartsDataZoom: vi.fn(),
}));

const interfaceMetadata = (id: string) => ({
  id,
  name: 'ether1',
  kind: 'wan',
  hardware_id: id,
  aggregate: false,
  first_seen_at_ms: 10,
  last_seen_at_ms: 20,
});

function trafficResponse(): TrafficHistoryResponse {
  return {
    schema_version: 4,
    router: {
      id: 'router-1',
      hardware_identity: 'serial-1',
      fallback_target: '192.168.88.1',
      identity_source: 'hardware',
      first_seen_at_ms: 10,
      last_seen_at_ms: 20,
    },
    interface: {
      id: '__aggregate__',
      name: 'Aggregate',
      kind: 'aggregate',
      hardware_id: null,
      aggregate: true,
      first_seen_at_ms: 10,
      last_seen_at_ms: 20,
    },
    wan_interfaces: [interfaceMetadata('*1'), interfaceMetadata('*2')],
    wan_names: ['ether1'],
    points: [],
    totals: {
      download_bytes: '0',
      upload_bytes: '0',
      exact_download_bytes: '0',
      exact_upload_bytes: '0',
      estimated_download_bytes: '0',
      estimated_upload_bytes: '0',
      estimated: false,
      complete: true,
      coverage_ratio: 1,
    },
    coverage: {
      requested_duration_ms: 1_000,
      exact_duration_ms: 1_000,
      estimated_duration_ms: 0,
      covered_duration_ms: 1_000,
      completeness: 1,
      gap_count: 0,
    },
    bucket_size_ms: 1_000,
    interval_secs: 1,
  };
}

describe('TrafficView interface selection', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    apiMocks.fetchTrafficHistory.mockReset();
    apiMocks.fetchTrafficHistory.mockResolvedValue(trafficResponse());
  });

  it('disambiguates duplicate names and queries by canonical interface id', async () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    const wrapper = mount(TrafficView, {
      global: {
        plugins: [pinia],
        stubs: { FeatherIcon: true },
      },
    });
    await flushPromises();

    const selector = wrapper.get('select[aria-label="选择 WAN 接口"]');
    expect(selector.findAll('option').map((option) => option.text())).toEqual([
      '全部 (合计)',
      'ether1 (*1)',
      'ether1 (*2)',
    ]);

    await selector.setValue('*2');
    await flushPromises();

    expect(apiMocks.fetchTrafficHistory).toHaveBeenLastCalledWith(
      expect.any(Number),
      expect.any(Number),
      { interfaceId: '*2' },
      expect.any(AbortSignal),
    );
  });
});
