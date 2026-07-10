<script setup lang="ts">
import { useDashboardStore } from '@/stores/dashboard';
import { useWebSocketStore } from '@/stores/websocket';
import { computed } from 'vue';
import SystemStatusCard from '@/components/dashboard/SystemStatusCard.vue';
import IspProbeCard from '@/components/dashboard/IspProbeCard.vue';
import TrafficChart from '@/components/dashboard/TrafficChart.vue';
import IspStabilityBar from '@/components/dashboard/IspStabilityBar.vue';
import InterfaceStatusCard from '@/components/dashboard/InterfaceStatusCard.vue';
import ConnectedDevicesCard from '@/components/dashboard/ConnectedDevicesCard.vue';
import FeatherIcon from '@/components/shared/FeatherIcon.vue';

const dashboardStore = useDashboardStore();
const wsStore = useWebSocketStore();

const connectionLabel = computed(() => {
  if (!dashboardStore.wsConnected) return 'WebSocket 未连接';
  if (!dashboardStore.routerosConnected) return 'RouterOS 未连接';
  if (!dashboardStore.isLive) return '实时数据已过期';
  return null;
});
</script>

<template>
  <div class="dashboard-grid">

    <!-- Connection Banner -->
    <div v-if="connectionLabel" class="connection-banner">
      <FeatherIcon name="alert-triangle" :size="16" />
      <span>{{ connectionLabel }}</span>
      <span class="banner-status">
        WS: {{ wsStore.connectionState }}
      </span>
    </div>

    <!-- Left Column: 30% -->
    <div class="dashboard-left">
      <SystemStatusCard />
      <IspProbeCard />
    </div>

    <!-- Right Column: 70% — 3 stacked areas -->
    <section class="dashboard-right">
      <!-- Area 1: Traffic Chart -->
      <TrafficChart />

      <!-- Area 2: ISP Stability -->
      <IspStabilityBar />

      <!-- Area 3: Two side-by-side cards -->
      <div class="two-card-row">
        <InterfaceStatusCard />
        <ConnectedDevicesCard />
      </div>
    </section>
  </div>
</template>

<style scoped>
.connection-banner {
  grid-column: 1 / -1;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 16px;
  background: var(--color-danger-subtle);
  border: 1px solid rgba(239, 68, 68, 0.2);
  border-radius: var(--border-radius-md);
  color: var(--color-danger);
  font-size: 0.8rem;
  font-weight: 500;
}

.banner-status {
  margin-left: auto;
  font-family: var(--font-mono);
  font-size: 0.7rem;
}
</style>
