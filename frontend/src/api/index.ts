/**
 * REST API wrapper for backend health/config endpoints.
 * Primary data flow is through WebSocket; this is for auxiliary REST calls.
 */

const API_BASE = '/api';

async function request<T>(url: string): Promise<T> {
  const res = await fetch(`${API_BASE}${url}`);
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export interface HealthResponse {
  status: string;
  uptime: string;
  ws_connections: number;
  version: string;
}

export interface ConfigResponse {
  routeros_host: string;
  routeros_port: number;
  routeros_scheme: string;
  poll_interval_secs: number;
  probe_interval_secs: number;
}

export async function fetchHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health');
}

export async function fetchConfig(): Promise<ConfigResponse> {
  return request<ConfigResponse>('/config');
}

export interface TrafficHistoryPoint {
  timestamp_ms: number;
  download_bps: number;
  upload_bps: number;
  wan_name?: string | null;
}

export interface TrafficHistoryResponse {
  points: TrafficHistoryPoint[];
  interval_secs: number;
  wan_names?: string[];
}

export async function fetchTrafficHistory(
  start: number,
  end: number,
  wanName?: string,
): Promise<TrafficHistoryResponse> {
  let url = `/traffic?start=${start}&end=${end}`;
  if (wanName) {
    url += `&wan_name=${encodeURIComponent(wanName)}`;
  }
  return request<TrafficHistoryResponse>(url);
}

// ── Device Overrides ─────────────────────────────────────────

export interface DeviceOverride {
  mac: string;
  custom_name: string | null;
  custom_type: string | null;
  updated_at: number;
}

export interface UpdateOverrideRequest {
  custom_name?: string | null;
  custom_type?: string | null;
}

export async function fetchDeviceOverrides(): Promise<DeviceOverride[]> {
  return request<DeviceOverride[]>('/devices');
}

export async function updateDeviceOverride(
  mac: string,
  data: UpdateOverrideRequest,
): Promise<DeviceOverride[]> {
  const encodedMac = encodeURIComponent(mac);
  const res = await fetch(`${API_BASE}/devices/${encodedMac}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

// ── Config / Settings ──────────────────────────────────────

export interface FullConfig {
  routeros_host: string;
  routeros_port: number;
  routeros_scheme: string;
  routeros_username: string;
  routeros_password: string;
  accept_invalid_certs: boolean;
  poll_interval_secs: number;
  probe_interval_secs: number;
  db_raw_retention_days: number;
  db_total_retention_days: number;
  latency_good_ms: number;
  latency_poor_ms: number;
  theme: string;
  routeros_configured: boolean;
  wizard_completed: boolean;
}

export interface ConfigUpdateResult {
  saved: string[];
  requires_restart: string[];
}

export interface ConnectionTestResult {
  success: boolean;
  model?: string;
  version?: string;
  error?: string;
}

export async function fetchFullConfig(): Promise<FullConfig> {
  return request<FullConfig>('/config');
}

export async function updateConfig(
  patch: Record<string, unknown>,
): Promise<ConfigUpdateResult> {
  const res = await fetch(`${API_BASE}/config`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(patch),
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function testConnection(
  params?: Record<string, unknown>,
): Promise<ConnectionTestResult> {
  const res = await fetch(`${API_BASE}/config/test-connection`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params || {}),
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

// ── Probe Targets ─────────────────────────────────────────────

export interface ProbeTarget {
  id?: number;       // absent for new items
  name: string;
  host: string;
  category: string;
  sort_order?: number;
}

export interface ProbeTargetsResponse {
  targets: ProbeTarget[];
}

export async function fetchProbeTargets(): Promise<ProbeTargetsResponse> {
  return request<ProbeTargetsResponse>('/probes');
}

export async function updateProbeTargets(
  targets: ProbeTarget[],
): Promise<ProbeTargetsResponse> {
  const res = await fetch(`${API_BASE}/probes`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(targets),
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function resetProbeTargets(): Promise<ProbeTargetsResponse> {
  const res = await fetch(`${API_BASE}/probes/reset`, {
    method: 'POST',
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}
