<script setup lang="ts">
import { computed, ref, watch, onMounted, nextTick } from 'vue';
import { useThemeStore } from '@/stores/theme';
import { useDashboardStore } from '@/stores/dashboard';
import { storeToRefs } from 'pinia';
import { useECharts } from '@/composables/useECharts';
import FeatherIcon from '@/components/shared/FeatherIcon.vue';
import {
  buildTrafficChartOption,
  formatBitrate,
  formatBytes,
  HISTORY_TIME_RANGE_OPTIONS,
  timeRangeToMs,
  type TimeRange,
  type TrafficChartData,
} from '@/types/charts';
import { fetchTrafficHistory, type TrafficHistoryResponse } from '@/api/index';

const themeStore = useThemeStore();
const dashboardStore = useDashboardStore();
const { hasMultipleWans, wanNames, selectedWan } = storeToRefs(dashboardStore);
const isDark = computed(() => themeStore.mode === 'dark');
const { chartRef, initChart, updateOption, dispose } = useECharts(isDark);

const selectedRange = ref<TimeRange | 'custom'>('6H');
const customStart = ref('');
const customEnd = ref('');
const loading = ref(false);
const error = ref<string | null>(null);
const chartData = ref<TrafficChartData[]>([]);
const intervalSecs = ref(5);
const totalDownload = ref(0);
const totalUpload = ref(0);

function rangeLabel(range: TimeRange | 'custom'): string {
  if (range === 'custom') return '自定义';
  const opt = HISTORY_TIME_RANGE_OPTIONS.find(o => o.key === range);
  return opt?.label || range;
}

async function loadHistory(range: TimeRange | 'custom') {
  loading.value = true;
  error.value = null;

  let startMs: number;
  let endMs: number;

  if (range === 'custom') {
    if (!customStart.value || !customEnd.value) {
      loading.value = false;
      return;
    }
    startMs = new Date(customStart.value).getTime();
    endMs = new Date(customEnd.value).getTime();
    if (endMs <= startMs) {
      error.value = '结束时间必须大于开始时间';
      loading.value = false;
      return;
    }
  } else {
    endMs = Date.now();
    startMs = endMs - timeRangeToMs(range);
  }

  try {
    const resp: TrafficHistoryResponse = await fetchTrafficHistory(
      startMs,
      endMs,
      selectedWan.value ?? undefined,
    );

    chartData.value = resp.points.map((p) => ({
      timestamp: new Date(p.timestamp_ms).toISOString(),
      download_bps: p.download_bps,
      upload_bps: p.upload_bps,
    }));
    intervalSecs.value = resp.interval_secs;

    // Compute totals from the raw data
    let dlTotal = 0;
    let ulTotal = 0;
    for (const p of resp.points) {
      dlTotal += p.download_bps * resp.interval_secs;
      ulTotal += p.upload_bps * resp.interval_secs;
    }
    totalDownload.value = dlTotal;
    totalUpload.value = ulTotal;

    await nextTick();
    renderChart();
  } catch (e: any) {
    error.value = e.message || '加载失败';
  } finally {
    loading.value = false;
  }
}

function renderChart() {
  if (!chartRef.value || chartData.value.length === 0) return;
  const option = buildTrafficChartOption(
    chartData.value,
    isDark.value,
    selectedRange.value === 'custom' ? '7D' : selectedRange.value,
    { dataZoom: true },
  );
  const el = chartRef.value as HTMLElement;
  if ((el as any).__echart_instance) {
    updateOption(option, false);
  } else {
    initChart(option);
  }
}

function selectRange(range: TimeRange) {
  selectedRange.value = range;
  loadHistory(range);
}

function selectCustom() {
  selectedRange.value = 'custom';
  // Default to last 24h
  const now = new Date();
  customEnd.value = toLocalDatetime(now);
  const start = new Date(now.getTime() - 24 * 3600 * 1000);
  customStart.value = toLocalDatetime(start);
}

function toLocalDatetime(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function applyCustom() {
  if (!customStart.value || !customEnd.value) return;
  loadHistory('custom');
}

// Re-render on theme change
watch(isDark, () => {
  nextTick(() => {
    dispose();
    nextTick(renderChart);
  });
});

// Re-fetch when WAN selection changes
watch(selectedWan, () => {
  loadHistory(selectedRange.value);
});

onMounted(() => {
  loadHistory(selectedRange.value);
});
</script>

<template>
  <div class="traffic-view">
    <div class="card traffic-card">
      <!-- Header -->
      <div class="traffic-header">
        <div class="traffic-title-row">
          <FeatherIcon name="bar-chart-2" :size="18" />
          <span class="traffic-title">流量历史</span>
        </div>
        <!-- Time range presets -->
        <div class="range-controls">
          <div class="range-controls-top">
            <select
              v-if="hasMultipleWans"
              class="wan-select"
              :value="selectedWan ?? ''"
              @change="dashboardStore.selectWan($event.target ? ($event.target as HTMLSelectElement).value || null : null)"
            >
              <option value="">全部 (合计)</option>
              <option v-for="name in wanNames" :key="name" :value="name">{{ name }}</option>
            </select>

            <div class="time-range-switcher">
              <button
                v-for="opt in HISTORY_TIME_RANGE_OPTIONS"
                :key="opt.key"
                class="time-btn"
                :class="{ active: selectedRange === opt.key }"
                :disabled="loading"
                @click="selectRange(opt.key)"
              >
                {{ opt.label }}
              </button>
              <button
                class="time-btn"
                :class="{ active: selectedRange === 'custom' }"
                :disabled="loading"
                @click="selectCustom"
              >
                自定义
              </button>
            </div>
          </div>

          <!-- Custom date range inputs -->
          <div v-if="selectedRange === 'custom'" class="custom-range">
            <input
              type="datetime-local"
              class="date-input"
              v-model="customStart"
              :max="customEnd"
            />
            <span class="date-sep">—</span>
            <input
              type="datetime-local"
              class="date-input"
              v-model="customEnd"
              :min="customStart"
            />
            <button class="apply-btn" :disabled="loading" @click="applyCustom">
              <FeatherIcon name="search" :size="14" />
              <span>查询</span>
            </button>
          </div>
        </div>
      </div>

      <!-- Summary stats -->
      <div class="traffic-summary">
        <div class="summary-item download">
          <FeatherIcon name="download" :size="14" />
          <div class="summary-text">
            <span class="summary-label">总下载</span>
            <span class="summary-value mono">{{ formatBytes(totalDownload) }}</span>
          </div>
        </div>
        <div class="summary-item upload">
          <FeatherIcon name="upload" :size="14" />
          <div class="summary-text">
            <span class="summary-label">总上传</span>
            <span class="summary-value mono">{{ formatBytes(totalUpload) }}</span>
          </div>
        </div>
        <div class="summary-item meta">
          <span class="summary-label">数据间隔</span>
          <span class="summary-value mono">{{ intervalSecs }}s</span>
        </div>
      </div>

      <!-- Chart -->
      <div class="chart-body">
        <!-- Loading -->
        <div v-if="loading && chartData.length === 0" class="chart-state">
          <span class="spinner" />
          <span>加载中...</span>
        </div>

        <!-- Error -->
        <div v-else-if="error && chartData.length === 0" class="chart-state error">
          <FeatherIcon name="alert-triangle" :size="24" />
          <span>{{ error }}</span>
          <button class="retry-btn" @click="loadHistory(selectedRange)">重试</button>
        </div>

        <!-- No data -->
        <div v-else-if="chartData.length === 0" class="chart-state">
          <FeatherIcon name="bar-chart-2" :size="48" :stroke-width="1" />
          <span>所选范围内暂无流量数据</span>
        </div>

        <!-- Chart -->
        <div
          v-show="chartData.length > 0"
          ref="chartRef"
          class="chart-canvas"
        />
      </div>
    </div>
  </div>
</template>

<style scoped>
.traffic-view {
  padding: var(--content-gap);
  height: calc(100vh - var(--navbar-height));
  overflow: hidden;
}

.traffic-card {
  display: flex;
  flex-direction: column;
  gap: 16px;
  height: 100%;
  overflow: hidden;
}

.traffic-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
  flex-shrink: 0;
}

.traffic-title-row {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--color-text-secondary);
}

.traffic-title {
  font-weight: 600;
  font-size: 1rem;
  color: var(--color-text-primary);
}

.range-controls {
  display: flex;
  flex-direction: column;
  gap: 8px;
  align-items: flex-end;
}

.range-controls-top {
  display: flex;
  align-items: center;
  gap: 8px;
}

.wan-select {
  padding: 5px 8px;
  font-size: 0.75rem;
  font-weight: 500;
  font-family: var(--font-sans);
  border: 1px solid var(--color-border-light);
  border-radius: var(--border-radius-sm);
  background: var(--color-bg-input);
  color: var(--color-text-primary);
  cursor: pointer;
  outline: none;
  transition: border-color var(--transition-fast);
}

.wan-select:focus {
  border-color: var(--color-accent);
}

.time-range-switcher {
  display: flex;
  border: 1px solid var(--color-border-light);
  border-radius: var(--border-radius-sm);
  overflow: hidden;
  background: var(--color-bg-input);
}

.custom-range {
  display: flex;
  align-items: center;
  gap: 8px;
}

.date-input {
  padding: 5px 8px;
  font-size: 0.75rem;
  font-family: var(--font-mono);
  border: 1px solid var(--color-border-light);
  border-radius: var(--border-radius-sm);
  background: var(--color-bg-input);
  color: var(--color-text-primary);
  outline: none;
  transition: border-color var(--transition-fast);
}

.date-input:focus {
  border-color: var(--color-accent);
}

.date-sep {
  color: var(--color-text-muted);
  font-size: 0.8rem;
}

.apply-btn {
  display: flex;
  align-items: center;
  gap: 5px;
  padding: 5px 12px;
  font-size: 0.78rem;
  font-weight: 500;
  border: 1px solid var(--color-accent-border);
  border-radius: var(--border-radius-sm);
  background: var(--color-accent-subtle);
  color: var(--color-accent);
  cursor: pointer;
  font-family: var(--font-sans);
  transition: all var(--transition-fast);
}

.apply-btn:hover:not(:disabled) {
  background: var(--color-accent);
  color: #fff;
}

.apply-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.time-btn {
  padding: 5px 14px;
  font-size: 0.78rem;
  font-weight: 500;
  border: none;
  background: transparent;
  color: var(--color-text-secondary);
  cursor: pointer;
  font-family: var(--font-sans);
  transition: all var(--transition-fast);
  white-space: nowrap;
}

.time-btn:hover:not(:disabled) {
  color: var(--color-text-primary);
  background: var(--color-bg-hover);
}

.time-btn.active {
  background: var(--color-accent);
  color: #fff;
  font-weight: 600;
}

.time-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.traffic-summary {
  display: flex;
  gap: 20px;
  padding: 12px 16px;
  background: var(--color-bg-input);
  border-radius: var(--border-radius-sm);
  border: 1px solid var(--color-border-light);
  flex-shrink: 0;
  flex-wrap: wrap;
}

.summary-item {
  display: flex;
  align-items: center;
  gap: 8px;
}

.summary-item.download { color: var(--color-accent); }
.summary-item.upload { color: var(--color-success); }
.summary-item.meta { color: var(--color-text-muted); margin-left: auto; }

.summary-text {
  display: flex;
  flex-direction: column;
}

.summary-label {
  font-size: 0.65rem;
  color: var(--color-text-muted);
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.summary-value {
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--color-text-primary);
}

.chart-body {
  flex: 1;
  min-height: 0;
  position: relative;
}

.chart-canvas {
  width: 100%;
  height: 100%;
  min-height: 300px;
}

.chart-state {
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

.chart-state.error {
  color: var(--color-danger);
}

.retry-btn {
  padding: 6px 16px;
  border: 1px solid var(--color-border);
  border-radius: var(--border-radius-sm);
  background: var(--color-bg-input);
  color: var(--color-text-primary);
  cursor: pointer;
  font-size: 0.8rem;
  font-family: var(--font-sans);
  transition: all var(--transition-fast);
}

.retry-btn:hover {
  background: var(--color-bg-hover);
}

/* Spinner — simple CSS animation */
.spinner {
  width: 24px;
  height: 24px;
  border: 3px solid var(--color-border-light);
  border-top-color: var(--color-accent);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

/* Portrait adjustments */
@media (orientation: portrait) {
  .time-range-switcher {
    width: 100%;
    justify-content: center;
  }

  .time-btn {
    flex: 1;
    padding: 6px 8px;
    font-size: 0.72rem;
  }

  .traffic-summary {
    gap: 12px;
  }
}
</style>
