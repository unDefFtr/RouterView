import { beforeEach, describe, expect, it, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import ProbeTargetEditor from './ProbeTargetEditor.vue';

const apiMocks = vi.hoisted(() => ({
  fetchProbeTargets: vi.fn(),
  resetProbeTargets: vi.fn(),
  updateProbeTargets: vi.fn(),
}));

vi.mock('@/api', async (importOriginal) => ({
  ...await importOriginal<typeof import('@/api')>(),
  ...apiMocks,
}));

describe('ProbeTargetEditor keyboard ordering', () => {
  beforeEach(() => {
    apiMocks.fetchProbeTargets.mockReset();
    apiMocks.resetProbeTargets.mockReset();
    apiMocks.updateProbeTargets.mockReset();
    apiMocks.fetchProbeTargets.mockResolvedValue({
      targets: [
        { name: 'DNS A', host: '1.1.1.1', category: 'dns', sort_order: 0 },
        { name: 'DNS B', host: '8.8.8.8', category: 'dns', sort_order: 1 },
        { name: 'Cloud', host: 'cloud.example', category: 'cloud', sort_order: 2 },
      ],
    });
  });

  it('moves adjacent targets with arrow keys without crossing categories', async () => {
    const wrapper = mount(ProbeTargetEditor, {
      global: { stubs: { FeatherIcon: true } },
    });
    await flushPromises();

    const names = () => wrapper
      .findAll<HTMLInputElement>('input[aria-label$="名称"]')
      .map((input) => input.element.value);

    await wrapper.findAll('.grip-handle')[0].trigger('keydown', { key: 'ArrowDown' });
    expect(names()).toEqual(['DNS B', 'DNS A', 'Cloud']);

    await wrapper.findAll('.grip-handle')[1].trigger('keydown', { key: 'ArrowDown' });
    expect(names()).toEqual(['DNS B', 'DNS A', 'Cloud']);
  });
});
