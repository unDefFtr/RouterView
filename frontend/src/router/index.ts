import { createRouter, createWebHistory } from 'vue-router';
import type { RouteRecordRaw } from 'vue-router';
import { fetchFullConfig } from '@/api';

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'dashboard',
    component: () => import('@/views/DashboardView.vue'),
    meta: { title: '网络概况', requiresWizard: true },
  },
  {
    path: '/devices',
    name: 'devices',
    component: () => import('@/views/DevicesView.vue'),
    meta: { title: '终端设备', requiresWizard: true },
  },
  {
    path: '/traffic',
    name: 'traffic',
    component: () => import('@/views/TrafficView.vue'),
    meta: { title: '流量历史', requiresWizard: true },
  },
  {
    path: '/settings',
    name: 'settings',
    component: () => import('@/views/SettingsView.vue'),
    meta: { title: '设置', requiresWizard: true },
  },
  {
    path: '/wizard',
    name: 'wizard',
    component: () => import('@/views/WizardView.vue'),
    meta: { title: '初始配置', fullScreen: true },
  },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});

// Global navigation guard — redirect to wizard if not yet configured.
router.beforeEach(async (to, _from, next) => {
  // Always allow navigation to the wizard itself.
  if (to.name === 'wizard') return next();

  // Only intercept routes that require wizard completion.
  if (!to.meta.requiresWizard) return next();

  try {
    const cfg = await fetchFullConfig();
    if (!cfg.wizard_completed) {
      return next({ name: 'wizard', replace: true });
    }
  } catch {
    // Backend unreachable — let the route through so the user sees
    // connection error state rather than being stuck on the wizard.
  }

  next();
});
