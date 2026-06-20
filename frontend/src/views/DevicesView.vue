<script setup lang="ts">
import { ref, computed } from 'vue';
import { useDashboardStore } from '@/stores/dashboard';
import { storeToRefs } from 'pinia';
import { useViewport } from '@/composables/useViewport';
import type { Device } from '@/types/dashboard';
import DeviceList from '@/components/devices/DeviceList.vue';
import DeviceDetail from '@/components/devices/DeviceDetail.vue';

const store = useDashboardStore();
const { wifi } = storeToRefs(store);
const { isPortrait } = useViewport();

const devices = computed(() => wifi.value.devices);
const selectedDevice = ref<Device | null>(null);

function selectDevice(device: Device) {
  selectedDevice.value = device;
}

function clearSelection() {
  selectedDevice.value = null;
}
</script>

<template>
  <div class="devices-grid" :class="{ portrait: isPortrait }">
    <!-- Device List — left column (landscape) or full width (portrait) -->
    <DeviceList
      :devices="devices"
      :selected-mac="selectedDevice?.mac ?? null"
      @select="selectDevice"
    />

    <!-- Landscape: detail panel in the right column -->
    <DeviceDetail
      v-if="!isPortrait"
      :device="selectedDevice"
      :is-overlay="false"
    />

    <!-- Portrait: full-screen overlay when a device is selected -->
    <Teleport to="body" v-if="isPortrait && selectedDevice">
      <div class="device-overlay">
        <DeviceDetail
          :device="selectedDevice"
          :is-overlay="true"
          @close="clearSelection"
        />
      </div>
    </Teleport>
  </div>
</template>

<style scoped>
.devices-grid {
  display: grid;
  grid-template-columns: 65% 1fr;
  gap: var(--content-gap);
  padding: var(--content-gap);
  height: calc(100vh - var(--navbar-height));
  overflow: hidden;
}

.devices-grid.portrait {
  grid-template-columns: 1fr;
}

.device-overlay {
  position: fixed;
  inset: 0;
  z-index: 300;
  background: var(--color-bg-primary);
  display: flex;
  flex-direction: column;
}
</style>
