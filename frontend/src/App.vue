<script setup lang="ts">
import MainLayout from '@/components/layout/MainLayout.vue';
import { useWebSocketStore } from '@/stores/websocket';
import { useDashboardStore } from '@/stores/dashboard';
import { useDeviceOverrides } from '@/composables/useDeviceOverrides';
import { onMounted, onUnmounted } from 'vue';

const wsStore = useWebSocketStore();
const dashboardStore = useDashboardStore();
const { loadOverrides } = useDeviceOverrides();

onMounted(() => {
  // Connect WebSocket to the backend
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;
  wsStore.connect(wsUrl);
  // Load device overrides from the backend
  loadOverrides();
});

onUnmounted(() => {
  wsStore.disconnect();
});
</script>

<template>
  <MainLayout>
    <router-view />
  </MainLayout>
</template>
