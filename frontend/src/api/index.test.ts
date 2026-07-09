import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchTrafficHistory } from './index';

afterEach(() => vi.unstubAllGlobals());

describe('fetchTrafficHistory', () => {
  it('encodes the WAN name and forwards request cancellation', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      points: [],
      interval_secs: 5,
    }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const controller = new AbortController();

    await fetchTrafficHistory(100, 200, 'wan/a + backup', controller.signal);

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/traffic?start=100&end=200&wan_name=wan%2Fa%20%2B%20backup',
      { signal: controller.signal },
    );
  });
});
