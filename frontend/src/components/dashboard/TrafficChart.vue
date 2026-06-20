<script setup lang="ts">
import { computed, watch, ref, nextTick, onMounted } from 'vue';
import { useDashboardStore } from '@/stores/dashboard';
import { useThemeStore } from '@/stores/theme';
import { storeToRefs } from 'pinia';
import { useECharts } from '@/composables/useECharts';
import FeatherIcon from '@/components/shared/FeatherIcon.vue';
import {
  buildTrafficChartOption,
  formatBitrate,
  TIME_RANGE_OPTIONS,
  timeRangeToMs,
  type TimeRange,
  type TrafficChartData,
} from '@/types/charts';
import { fetchTrafficHistory, type TrafficHistoryResponse } from '@/api/index';

const dashboardStore = useDashboardStore();
const themeStore = useThemeStore();
const { trafficPoints, trafficTimeRange, totalDownloadBps, totalUploadBps } =
  storeToRefs(dashboardStore);

const isDark = computed(() => themeStore.mode === 'dark');
const { chartRef, initChart, updateOption, dispose } = useECharts(isDark);

const downloadRateStr = computed(() => formatBitrate(totalDownloadBps.value));
const uploadRateStr = computed(() => formatBitrate(totalUploadBps.value));

// Historical backfill from API — survives server restarts
const historyPoints = ref<TrafficChartData[]>([]);
const historyLoading = ref(false);

async function loadHistory(range: TimeRange) {
  historyLoading.value = true;
  try {
    const endMs = Date.now();
    const startMs = endMs - timeRangeToMs(range);
    const resp: TrafficHistoryResponse = await fetchTrafficHistory(startMs, endMs);
    historyPoints.value = resp.points.map((p) => ({
      timestamp: new Date(p.timestamp_ms).toISOString(),
      download_bps: p.download_bps,
      upload_bps: p.upload_bps,
    }));
  } catch {
    // API unavailable — fall back to WS-only data
  } finally {
    historyLoading.value = false;
  }
}

// Merge WS live data with API history. WS timestamps take priority.
const mergedPoints = computed<TrafficChartData[]>(() => {
  const wsMap = new Map<string, TrafficChartData>();
  for (const p of trafficPoints.value) {
    wsMap.set(p.timestamp, p);
  }
  const merged = new Map<string, TrafficChartData>();
  // API history first (base layer)
  for (const p of historyPoints.value) {
    merged.set(p.timestamp, p);
  }
  // WS data overwrites (more real-time)
  for (const [ts, p] of wsMap) {
    merged.set(ts, p);
  }
  return Array.from(merged.values()).sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
  );
});

// Build & update chart when data or theme changes
function renderChart() {
  const option = buildTrafficChartOption(
    mergedPoints.value,
    isDark.value,
    trafficTimeRange.value,
  );
  if (!chartRef.value) return;

  const chartEl = chartRef.value as HTMLElement;
  const existing = (chartEl as any).__echart_instance;
  if (existing) {
    updateOption(option, false);
  } else {
    initChart(option);
  }
}

// Watch for data changes
watch(
  () => [mergedPoints.value.length, isDark.value, trafficTimeRange.value],
  () => {
    nextTick(renderChart);
  },
  { deep: false },
);

// Watch for theme changes
watch(isDark, () => {
  nextTick(() => {
    dispose();
    nextTick(renderChart);
  });
});

// Reload history when range changes
watch(trafficTimeRange, (range) => {
  loadHistory(range);
});

function selectTimeRange(range: TimeRange) {
  dashboardStore.setTrafficTimeRange(range);
}

onMounted(() => {
  loadHistory(trafficTimeRange.value);
});
</script>

<template>
  <div class="card traffic-chart">
    <!-- Top Controls -->
    <div class="chart-controls">
      <div class="chart-title-row">
        <div class="chart-selector">
          <FeatherIcon name="activity" :size="16" />
          <span class="chart-title">互联网流量</span>
        </div>
        <div class="chart-rates">
          <div class="rate-item download">
            <FeatherIcon name="download" :size="12" :stroke-width="2.5" />
            <span class="rate-label">下载</span>
            <span class="rate-value mono">{{ downloadRateStr }}</span>
          </div>
          <div class="rate-item upload">
            <FeatherIcon name="upload" :size="12" :stroke-width="2.5" />
            <span class="rate-label">上传</span>
            <span class="rate-value mono">{{ uploadRateStr }}</span>
          </div>
        </div>
      </div>

      <!-- Time Range Switcher -->
      <div class="time-range-switcher">
        <button
          v-for="opt in TIME_RANGE_OPTIONS"
          :key="opt.key"
          class="time-btn"
          :class="{ active: trafficTimeRange === opt.key }"
          @click="selectTimeRange(opt.key)"
        >
          {{ opt.label }}
        </button>
      </div>
    </div>

    <!-- Chart Area -->
    <div class="chart-container">
      <div
        v-if="mergedPoints.length === 0"
        class="chart-placeholder"
      >
        <FeatherIcon name="activity" :size="48" :stroke-width="1" />
        <span v-if="historyLoading">加载历史数据...</span>
        <span v-else>暂无流量数据</span>
      </div>
      <div ref="chartRef" class="chart-canvas" />
    </div>
  </div>
</template>

<style scoped>
.traffic-chart {
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 320px;
}

.chart-controls {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  flex-wrap: wrap;
  gap: 8px;
}

.chart-title-row {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.chart-selector {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--color-text-secondary);
}

.chart-title {
  font-weight: 600;
  font-size: 0.9rem;
  color: var(--color-text-primary);
}

.chart-rates {
  display: flex;
  gap: 16px;
}

.rate-item {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 0.75rem;
}

.rate-item.download {
  color: var(--color-success);
}

.rate-item.upload {
  color: var(--color-accent);
}

.rate-label {
  opacity: 0.7;
}

.rate-value {
  font-weight: 600;
}

.time-range-switcher {
  display: flex;
  border: 1px solid var(--color-border-light);
  border-radius: var(--border-radius-sm);
  overflow: hidden;
  background: var(--color-bg-input);
}

.time-btn {
  padding: 4px 12px;
  font-size: 0.75rem;
  font-weight: 500;
  border: none;
  background: transparent;
  color: var(--color-text-secondary);
  cursor: pointer;
  font-family: var(--font-sans);
  transition: all var(--transition-fast);
}

.time-btn:hover {
  color: var(--color-text-primary);
  background: var(--color-bg-hover);
}

.time-btn.active {
  background: var(--color-accent);
  color: #fff;
  font-weight: 600;
}

.chart-container {
  flex: 1;
  position: relative;
  min-height: 240px;
}

.chart-canvas {
  width: 100%;
  height: 100%;
  min-height: 240px;
}

.chart-placeholder {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 12px;
  color: var(--color-text-muted);
  font-size: 0.85rem;
}
</style>
