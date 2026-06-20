import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import type {
  SystemInfo,
  GatewayInfo,
  InterfaceSummary,
  IspInfo,
  LatencyProbe,
  TrafficPoint,
  WifiInfo,
  IspStability,
  InterfaceStatus,
  DashboardSnapshot,
  DashboardUpdate,
} from '@/types/dashboard';
import type { TimeRange } from '@/types/charts';
import { timeRangeToMs } from '@/types/charts';
import {
  DEFAULT_SYSTEM_INFO,
  DEFAULT_GATEWAY_INFO,
  DEFAULT_INTERFACE_SUMMARY,
  DEFAULT_ISP_INFO,
  DEFAULT_WIFI_INFO,
  DEFAULT_STABILITY,
} from '@/types/dashboard';

/**
 * Central dashboard data store.
 * All dashboard components read from this store reactively.
 */
export const useDashboardStore = defineStore('dashboard', () => {
  // ── State ───────────────────────────────────────────

  const system = ref<SystemInfo>({ ...DEFAULT_SYSTEM_INFO });
  const gateway = ref<GatewayInfo>({ ...DEFAULT_GATEWAY_INFO });
  const interfaces = ref<InterfaceSummary>({ ...DEFAULT_INTERFACE_SUMMARY });
  const isp = ref<IspInfo>({ ...DEFAULT_ISP_INFO });
  const latencyProbes = ref<LatencyProbe[]>([]);
  /// Full 6h rolling buffer – backend sends pruned history, we keep everything.
  const _trafficBuffer = ref<TrafficPoint[]>([]);
  const trafficTimeRange = ref<'5M' | '1H' | '6H' | '24H' | '7D' | '30D'>('1H');
  const wifi = ref<WifiInfo>({ ...DEFAULT_WIFI_INFO });
  const stability = ref<IspStability>({ ...DEFAULT_STABILITY });
  const interfaceStatuses = ref<InterfaceStatus[]>([]);

  const routerosConnected = ref(false);
  const lastPollTimestamp = ref<string | null>(null);
  const wsConnected = ref(false);

  // Track previous counter values for display
  const totalDownloadBps = ref(0);
  const totalUploadBps = ref(0);

  // ── Getters ─────────────────────────────────────────

  const isLive = computed(() => routerosConnected.value && wsConnected.value);
  const systemUptimeFormatted = computed(() => system.value.uptime || '—');
  const downloadRate = computed(() => formatRate(totalDownloadBps.value));
  const uploadRate = computed(() => formatRate(totalUploadBps.value));
  const onlineRateFormatted = computed(() => `${stability.value.online_rate.toFixed(1)}%`);
  /// Reactive viewport — sliced from full buffer on every time-range change.
  const trafficPoints = computed(() =>
    pruneByTimestamp(_trafficBuffer.value, trafficTimeRange.value),
  );

  // ── Actions ─────────────────────────────────────────

  function handleSnapshot(snapshot: DashboardSnapshot) {
    system.value = snapshot.system;
    gateway.value = snapshot.gateway;
    interfaces.value = snapshot.interfaces;
    isp.value = snapshot.isp;
    latencyProbes.value = snapshot.latency_probes;
    // Backend sends up to 6h of history — keep full buffer, viewport derived reactively
    _trafficBuffer.value = pruneByTimestamp(snapshot.traffic.points, '6H');
    wifi.value = snapshot.wifi;
    stability.value = snapshot.stability;
    interfaceStatuses.value = snapshot.interface_statuses;

    totalDownloadBps.value = snapshot.isp.download_bps;
    totalUploadBps.value = snapshot.isp.upload_bps;

    routerosConnected.value = true;
    lastPollTimestamp.value = snapshot.timestamp;
  }

  function handleUpdate(update: DashboardUpdate) {
    if (update.system) Object.assign(system.value, update.system);
    if (update.gateway) {
      Object.assign(gateway.value, update.gateway);
    }
    if (update.interfaces) Object.assign(interfaces.value, update.interfaces);
    if (update.isp) {
      Object.assign(isp.value, update.isp);
      totalDownloadBps.value = update.isp.download_bps;
      totalUploadBps.value = update.isp.upload_bps;
    }
    if (update.traffic) {
      _trafficBuffer.value.push(update.traffic);
      _trafficBuffer.value = pruneByTimestamp(_trafficBuffer.value, '6H');
    }
    if (update.latency_probes) latencyProbes.value = update.latency_probes;
    if (update.wifi) Object.assign(wifi.value, update.wifi);
    if (update.stability) Object.assign(stability.value, update.stability);
    if (update.interface_statuses) interfaceStatuses.value = update.interface_statuses;

    lastPollTimestamp.value = update.timestamp;
    routerosConnected.value = true;
  }

  function handleConnectionStatus(connected: boolean, lastPoll: string | null) {
    routerosConnected.value = connected;
    if (lastPoll) lastPollTimestamp.value = lastPoll;
  }

  function setTrafficTimeRange(range: TimeRange) {
    trafficTimeRange.value = range;
  }

  /** Filter traffic points by actual timestamp, keeping only those within the window. */
  function pruneByTimestamp(
    points: TrafficPoint[],
    range: TimeRange,
  ): TrafficPoint[] {
    const now = Date.now();
    const cutoff = now - timeRangeToMs(range);
    return points.filter((p) => new Date(p.timestamp).getTime() >= cutoff);
  }

  // ── Return ─────────────────────────────────────────

  return {
    // State
    system,
    gateway,
    interfaces,
    isp,
    latencyProbes,
    trafficPoints,
    trafficTimeRange,
    wifi,
    stability,
    interfaceStatuses,
    routerosConnected,
    lastPollTimestamp,
    wsConnected,
    totalDownloadBps,
    totalUploadBps,
    // Getters
    isLive,
    systemUptimeFormatted,
    downloadRate,
    uploadRate,
    onlineRateFormatted,
    // Actions
    handleSnapshot,
    handleUpdate,
    handleConnectionStatus,
    setTrafficTimeRange,
  };
});

function formatRate(bps: number): string {
  if (bps === 0) return '0 bps';
  const mbps = bps / 1_000_000;
  if (mbps >= 1) return `${mbps.toFixed(1)} Mbps`;
  const kbps = bps / 1_000;
  return `${kbps.toFixed(1)} Kbps`;
}
