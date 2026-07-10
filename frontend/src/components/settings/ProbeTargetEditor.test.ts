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
        { name: 'Cloud', host: 'cloud.example', category: 'cloud', sort_order: 1 },
        { name: 'DNS B', host: '8.8.8.8', category: 'dns', sort_order: 2 },
        { name: 'Repo', host: 'repo.example', category: 'repo', sort_order: 3 },
        { name: 'DNS C', host: '9.9.9.9', category: 'dns', sort_order: 4 },
      ],
    });
  });

  it('moves non-adjacent category peers while preserving the focused target', async () => {
    const wrapper = mount(ProbeTargetEditor, {
      global: { stubs: { FeatherIcon: true } },
      attachTo: document.body,
    });
    await flushPromises();

    const names = () => wrapper
      .findAll<HTMLInputElement>('input[aria-label$="名称"]')
      .map((input) => input.element.value);

    const moveDown = wrapper.get<HTMLButtonElement>('button[aria-label="下移 DNS A"]');
    moveDown.element.focus();
    await moveDown.trigger('click');
    await flushPromises();
    expect(names()).toEqual(['Cloud', 'DNS B', 'DNS A', 'Repo', 'DNS C']);
    expect(document.activeElement).toBe(moveDown.element);

    await moveDown.trigger('click');
    await flushPromises();
    expect(names()).toEqual(['Cloud', 'DNS B', 'Repo', 'DNS C', 'DNS A']);
    expect(moveDown.attributes('disabled')).toBeDefined();
    expect(document.activeElement).toBe(
      wrapper.get<HTMLButtonElement>('button[aria-label="上移 DNS A"]').element,
    );

    wrapper.unmount();
  });
});
