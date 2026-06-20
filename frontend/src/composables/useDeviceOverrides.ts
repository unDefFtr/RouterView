/**
 * Device override composable — manages user-assigned custom names and types
 * for devices. Overrides are loaded from the backend REST API and kept in a
 * reactive local map. The composable also provides helpers for display names
 * and types that prefer custom values over auto-detected ones.
 */
import { ref } from 'vue';
import type { Device } from '@/types/dashboard';
import {
  fetchDeviceOverrides,
  updateDeviceOverride as apiUpdateOverride,
} from '@/api';

interface OverrideEntry {
  custom_name: string | null;
  custom_type: string | null;
}

const overrideMap = ref<Map<string, OverrideEntry>>(new Map());
const loaded = ref(false);

export function useDeviceOverrides() {
  /** Load all overrides from the backend. Call once on app mount. */
  async function loadOverrides() {
    try {
      const overrides = await fetchDeviceOverrides();
      const map = new Map<string, OverrideEntry>();
      for (const o of overrides) {
        map.set(o.mac.toLowerCase(), {
          custom_name: o.custom_name,
          custom_type: o.custom_type,
        });
      }
      overrideMap.value = map;
      loaded.value = true;
    } catch (e) {
      console.error('[DeviceOverrides] Failed to load overrides:', e);
    }
  }

  /** Save a single override and update the local map immediately. */
  async function saveOverride(
    mac: string,
    custom_name: string | null,
    custom_type: string | null,
  ) {
    await apiUpdateOverride(mac, { custom_name, custom_type });
    // Update local map immediately for instant feedback
    const key = mac.toLowerCase();
    const newMap = new Map(overrideMap.value);
    if (custom_name === null && custom_type === null) {
      newMap.delete(key);
    } else {
      newMap.set(key, { custom_name, custom_type });
    }
    overrideMap.value = newMap;
  }

  /** Get the display name for a device — custom_name takes precedence. */
  function displayName(device: Device): string {
    return device.custom_name || device.hostname;
  }

  /** Get the display type for a device — custom_type takes precedence. */
  function displayType(device: Device): string {
    return device.custom_type || device.device_type;
  }

  /** Check whether a device has any user overrides. */
  function hasOverride(device: Device): boolean {
    return !!(device.custom_name || device.custom_type);
  }

  return {
    overrideMap,
    loaded,
    loadOverrides,
    saveOverride,
    displayName,
    displayType,
    hasOverride,
  };
}
