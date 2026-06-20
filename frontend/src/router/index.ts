import { createRouter, createWebHistory } from 'vue-router';
import type { RouteRecordRaw } from 'vue-router';

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'dashboard',
    component: () => import('@/views/DashboardView.vue'),
    meta: { title: '网络概况' },
  },
  {
    path: '/devices',
    name: 'devices',
    component: () => import('@/views/DevicesView.vue'),
    meta: { title: '终端设备' },
  },
  {
    path: '/traffic',
    name: 'traffic',
    component: () => import('@/views/TrafficView.vue'),
    meta: { title: '流量历史' },
  },
  {
    path: '/settings',
    name: 'settings',
    component: () => import('@/views/SettingsView.vue'),
    meta: { title: '设置' },
  },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});
