import { beforeEach, describe, expect, it, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import SessionsView from './SessionsView.vue';

const apiMocks = vi.hoisted(() => {
  class TestApiError extends Error {
    constructor(readonly status: number) {
      super(`HTTP ${status}`);
    }
  }
  return {
    ApiError: TestApiError,
    createPairing: vi.fn(),
    fetchSessions: vi.fn(),
    revokeSession: vi.fn(),
  };
});

vi.mock('@/api', () => apiMocks);

const sessions = [
  {
    id: 'browser-1',
    username: 'admin',
    role: 'admin',
    session_kind: 'standard',
    label: null,
    created_at: 1_700_000_000,
    last_seen_at: 1_700_000_100,
    expires_at: 1_700_086_400,
    active: true,
  },
  {
    id: 'fixed-1',
    username: 'admin',
    role: 'viewer',
    session_kind: 'fixed',
    label: 'Hall display',
    created_at: 1_700_000_000,
    last_seen_at: 1_700_000_100,
    expires_at: 1_700_086_400,
    active: true,
  },
];

describe('SessionsView', () => {
  beforeEach(() => {
    apiMocks.fetchSessions.mockReset();
    apiMocks.revokeSession.mockReset();
    apiMocks.fetchSessions.mockResolvedValue(sessions);
    apiMocks.revokeSession.mockResolvedValue(undefined);
  });

  it('shows standard and fixed sessions and allows either kind to be revoked', async () => {
    const wrapper = mount(SessionsView, {
      global: { stubs: { FeatherIcon: true } },
    });
    await flushPromises();

    const groups = wrapper.findAll('.session-group');
    expect(groups).toHaveLength(2);
    expect(groups[0].text()).toContain('浏览器会话');
    expect(groups[0].text()).toContain('admin 浏览器会话');
    expect(groups[1].text()).toContain('固定设备');
    expect(groups[1].text()).toContain('Hall display');

    await groups[0].get('button.revoke').trigger('click');
    await flushPromises();

    expect(apiMocks.revokeSession).toHaveBeenCalledWith('browser-1');
    expect(apiMocks.fetchSessions).toHaveBeenCalledTimes(2);
  });
});
