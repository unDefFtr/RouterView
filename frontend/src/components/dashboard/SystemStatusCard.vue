<script setup lang="ts">
import { computed } from 'vue';
import { useDashboardStore } from '@/stores/dashboard';
import { storeToRefs } from 'pinia';
import FeatherIcon from '@/components/shared/FeatherIcon.vue';

const store = useDashboardStore();
const { system, gateway, interfaces } = storeToRefs(store);

const memoryUsagePct = computed(() => {
  if (system.value.total_memory === 0) return 0;
  return ((1 - system.value.free_memory / system.value.total_memory) * 100).toFixed(0);
});

const hddUsagePct = computed(() => {
  if (system.value.total_hdd === 0) return 0;
  return ((1 - system.value.free_hdd / system.value.total_hdd) * 100).toFixed(0);
});

const cpuColor = computed(() => {
  const cpu = system.value.cpu_load;
  if (cpu > 80) return 'var(--color-danger)';
  if (cpu > 50) return 'var(--color-warning)';
  return 'var(--color-success)';
});
</script>

<template>
  <div class="card system-status-card">
    <!-- Header with device model -->
    <div class="card-header">
      <div class="device-icon">
        <FeatherIcon name="hard-drive" :size="28" :stroke-width="1.5" />
      </div>
      <div class="device-info">
        <div class="device-model">{{ system.model || 'RouterOS' }}</div>
        <div class="device-version">{{ system.version }}</div>
      </div>
      <div class="cpu-badge" :style="{ color: cpuColor }">
        <span class="cpu-value">{{ system.cpu_load.toFixed(0) }}%</span>
        <span class="cpu-label">CPU</span>
      </div>
    </div>

    <!-- Summary icons row -->
    <div class="summary-row">
      <div class="summary-item" :class="{ online: gateway.wan_online }">
        <FeatherIcon name="globe" :size="16" />
        <span class="summary-label">WAN</span>
        <span class="summary-value">{{ gateway.wan_online ? '在线' : '离线' }}</span>
      </div>
      <div class="summary-item">
        <FeatherIcon name="server" :size="16" />
        <span class="summary-label">以太网</span>
        <span class="summary-value">{{ interfaces.ethernet_count }}</span>
      </div>
      <div class="summary-item">
        <FeatherIcon name="monitor" :size="16" />
        <span class="summary-label">终端</span>
        <span class="summary-value">{{ interfaces.connected_devices }}</span>
      </div>
      <div class="summary-item" :class="{ online: interfaces.wifi_online }">
        <FeatherIcon name="wifi" :size="16" />
        <span class="summary-label">WiFi</span>
        <span class="summary-value">{{ interfaces.wifi_count }}</span>
      </div>
      <div class="summary-item">
        <FeatherIcon name="upload" :size="16" />
        <span class="summary-label">IP 分配</span>
        <span class="summary-value">{{ gateway.ip_allocations }}</span>
      </div>
    </div>

    <!-- Core metrics -->
    <div class="metrics-grid">
      <div class="metric-item">
        <span class="metric-label">运行时长</span>
        <span class="metric-value mono">{{ system.uptime }}</span>
      </div>
      <div class="metric-item">
        <span class="metric-label">WAN IP</span>
        <span class="metric-value mono wan-ip">{{ gateway.wan_ip }}</span>
      </div>
      <div class="metric-item">
        <span class="metric-label">网关</span>
        <span class="metric-value mono">{{ gateway.gateway_ip }}</span>
      </div>
      <div class="metric-item">
        <span class="metric-label">版本</span>
        <span class="metric-value mono">RouterOS {{ system.version }}</span>
      </div>
    </div>

    <!-- Memory / HDD bars -->
    <div class="resource-bars">
      <div class="resource-bar">
        <div class="resource-bar__header">
          <span>内存</span>
          <span class="mono">{{ memoryUsagePct }}%</span>
        </div>
        <div class="resource-bar__track">
          <div
            class="resource-bar__fill"
            :style="{ width: memoryUsagePct + '%', backgroundColor: 'var(--color-accent)' }"
          />
        </div>
      </div>
      <div class="resource-bar">
        <div class="resource-bar__header">
          <span>硬盘</span>
          <span class="mono">{{ hddUsagePct }}%</span>
        </div>
        <div class="resource-bar__track">
          <div
            class="resource-bar__fill"
            :style="{ width: hddUsagePct + '%', backgroundColor: 'var(--color-info)' }"
          />
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.system-status-card {
  display: flex;
  flex-direction: column;
  gap: 16px;
  flex: 0 0 auto;
}

.card-header {
  display: flex;
  align-items: center;
  gap: 12px;
}

.device-icon {
  width: 44px;
  height: 44px;
  border-radius: var(--border-radius-sm);
  background: var(--color-accent-subtle);
  color: var(--color-accent);
  display: flex;
  align-items: center;
  justify-content: center;
}

.device-model {
  font-weight: 600;
  font-size: 0.95rem;
  color: var(--color-text-primary);
}

.device-version {
  font-size: 0.75rem;
  color: var(--color-text-muted);
  font-family: var(--font-mono);
}

.cpu-badge {
  margin-left: auto;
  display: flex;
  align-items: baseline;
  gap: 2px;
  padding: 4px 8px;
  border-radius: var(--border-radius-sm);
  background: var(--color-bg-input);
  font-family: var(--font-mono);
}

.cpu-value {
  font-size: 1.1rem;
  font-weight: 700;
}

.cpu-label {
  font-size: 0.65rem;
  opacity: 0.7;
}

.summary-row {
  display: flex;
  gap: 4px;
  padding: 10px;
  background: var(--color-bg-input);
  border-radius: var(--border-radius-sm);
  border: 1px solid var(--color-border-light);
}

.summary-item {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  color: var(--color-text-muted);
  padding: 4px 2px;
  border-radius: 4px;
}

.summary-item.online {
  color: var(--color-success);
}

.summary-label {
  font-size: 0.6rem;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.summary-value {
  font-size: 1rem;
  font-weight: 700;
  font-family: var(--font-mono);
  color: var(--color-text-primary);
}

.metrics-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
}

.metric-item {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.metric-label {
  font-size: 0.7rem;
  color: var(--color-text-muted);
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.metric-value {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--color-text-primary);
}

.wan-ip {
  color: var(--color-accent);
}

.resource-bars {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.resource-bar__header {
  display: flex;
  justify-content: space-between;
  font-size: 0.7rem;
  margin-bottom: 4px;
  color: var(--color-text-secondary);
}

.resource-bar__track {
  height: 4px;
  background: var(--color-bg-input);
  border-radius: 2px;
  overflow: hidden;
}

.resource-bar__fill {
  height: 100%;
  border-radius: 2px;
  transition: width var(--transition-normal);
}
</style>
