/**
 * Shared navigation items and active-route detection.
 * Used by both LeftSidebar (desktop) and BottomNavBar (mobile portrait).
 */
import { computed } from 'vue';
import { useRouter, useRoute } from 'vue-router';

export interface NavItem {
  id: string;
  label: string;
  icon: string;
  route: string;
}

const ITEMS: NavItem[] = [
  { id: 'overview', label: '概览', icon: 'grid', route: '/' },
  { id: 'devices', label: '设备', icon: 'monitor', route: '/devices' },
  { id: 'traffic', label: '流量', icon: 'chart', route: '/traffic' },
  { id: 'settings', label: '设置', icon: 'settings', route: '/settings' },
];

const ID_BY_ROUTE_NAME: Record<string, string> = {
  dashboard: 'overview',
  devices: 'devices',
  traffic: 'traffic',
  settings: 'settings',
};

export function useNavigation() {
  const router = useRouter();
  const route = useRoute();

  const activeId = computed(() => {
    const name = typeof route.name === 'string' ? route.name : '';
    return ID_BY_ROUTE_NAME[name] || 'overview';
  });

  function navigate(item: NavItem) {
    if (item.route !== route.path) {
      router.push(item.route);
    }
  }

  return {
    items: ITEMS,
    activeId,
    navigate,
  };
}
