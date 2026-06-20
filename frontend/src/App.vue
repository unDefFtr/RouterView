<script setup lang="ts">
import { computed, onMounted, onUnmounted, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import MainLayout from '@/components/layout/MainLayout.vue';
import { useWebSocketStore } from '@/stores/websocket';
import { useDashboardStore } from '@/stores/dashboard';
import { useDeviceOverrides } from '@/composables/useDeviceOverrides';
import { fetchFullConfig } from '@/api';

const route = useRoute();
const router = useRouter();
const wsStore = useWebSocketStore();
const dashboardStore = useDashboardStore();
const { loadOverrides } = useDeviceOverrides();

// Whether the current route wants full-screen (no MainLayout chrome).
const isFullScreen = computed(() => !!route.meta.fullScreen);

let initialized = false;

function connectAndLoad() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;
  wsStore.connect(wsUrl);
  loadOverrides();
}

onMounted(async () => {
  // Check whether the welcome wizard has been completed.
  const config = await fetchFullConfig().catch(() => null);

  if (config && !config.wizard_completed) {
    router.push('/wizard');
    return;
  }

  // Normal startup — connect WebSocket and load overrides.
  connectAndLoad();
  initialized = true;
});

// When route changes away from wizard (or to any non-fullScreen page)
// and we haven't initialized yet, start the real-time connection.
watch(
  () => route.meta.fullScreen,
  (wasFullScreen) => {
    if (!wasFullScreen && !initialized) {
      connectAndLoad();
      initialized = true;
    }
  },
);

onUnmounted(() => {
  wsStore.disconnect();
});
</script>

<template>
  <MainLayout v-if="!isFullScreen">
    <router-view />
  </MainLayout>
  <router-view v-else />
</template>
