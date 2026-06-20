<script setup lang="ts">
import { useDashboardStore } from '@/stores/dashboard';
import { useThemeStore } from '@/stores/theme';
import { computed } from 'vue';
import { useRoute } from 'vue-router';
import LiveIndicator from '@/components/shared/LiveIndicator.vue';
import FeatherIcon from '@/components/shared/FeatherIcon.vue';

const dashboardStore = useDashboardStore();
const themeStore = useThemeStore();
const route = useRoute();

const isLive = computed(() => dashboardStore.routerosConnected);
const themeIcon = computed(() => {
  if (themeStore.preference === 'system') return 'monitor';
  return themeStore.mode === 'dark' ? 'moon' : 'sun';
});
const themeLabel = computed(() => {
  if (themeStore.preference === 'system') return '跟随系统';
  return themeStore.mode === 'dark' ? '暗色模式' : '亮色模式';
});

const pageTitle = computed(() => {
  const meta = route.meta as { title?: string } | undefined;
  return meta?.title || 'RouterView';
});
</script>

<template>
  <div style="display: flex; align-items: center; width: 100%; height: 100%;">

    <!-- Left: Brand -->
    <div class="navbar-left">
      <div class="brand">
        <svg width="28" height="28" viewBox="0 0 32 32" fill="none" class="brand-logo">
          <rect width="32" height="32" rx="6" fill="var(--color-bg-card)"/>
          <path d="M16 6L6 12V20L16 26L26 20V12L16 6Z" stroke="var(--color-accent)" stroke-width="1.5" fill="none"/>
          <circle cx="16" cy="16" r="3" fill="var(--color-success)"/>
        </svg>
        <span class="brand-name">RouterView</span>
      </div>
    </div>

    <!-- Center: Title -->
    <div class="navbar-center">
      <h2 class="navbar-title">{{ pageTitle }}</h2>
    </div>

    <!-- Right: Status -->
    <div class="navbar-right">
      <LiveIndicator :connected="isLive" />

      <button class="theme-toggle" @click="themeStore.toggle()" :title="themeLabel">
        <FeatherIcon :name="themeIcon" :size="18" />
      </button>

      <button class="icon-btn" title="通知">
        <FeatherIcon name="bell" :size="20" />
      </button>

      <div class="avatar">
        <span>A</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.brand {
  display: flex;
  align-items: center;
  gap: 8px;
}

.brand-logo {
  flex-shrink: 0;
}

.brand-name {
  font-weight: 700;
  font-size: 1rem;
  color: var(--color-text-primary);
  letter-spacing: -0.02em;
}

.navbar-title {
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--color-text-primary);
}

.theme-toggle {
  width: 32px;
  height: 32px;
  aspect-ratio: 1;
  flex-shrink: 0;
  border: none;
  border-radius: var(--border-radius-sm);
  background: transparent;
  cursor: pointer;
  color: var(--color-text-secondary);
  display: flex;
  align-items: center;
  justify-content: center;
  transition: background var(--transition-fast);
}

.theme-toggle:hover {
  background: var(--color-bg-hover);
}

.icon-btn {
  width: 36px;
  height: 36px;
  aspect-ratio: 1;
  flex-shrink: 0;
  border: none;
  border-radius: var(--border-radius-sm);
  background: transparent;
  color: var(--color-text-secondary);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all var(--transition-fast);
}

.icon-btn:hover {
  background: var(--color-bg-hover);
  color: var(--color-text-primary);
}

.avatar {
  width: 32px;
  height: 32px;
  aspect-ratio: 1;
  flex-shrink: 0;
  border-radius: 50%;
  background: var(--color-accent);
  color: var(--color-text-inverse);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.85rem;
  font-weight: 600;
  cursor: pointer;
}
</style>
