import { onMounted, onUnmounted, ref, type Ref } from 'vue';
import * as echarts from 'echarts';
import type { EChartsOption } from 'echarts';

/**
 * Composable for managing an ECharts instance lifecycle.
 * Handles init, resize, theme-aware re-init, and dispose.
 */
export function useECharts(darkMode: Ref<boolean>) {
  const chartRef = ref<HTMLDivElement | null>(null);
  let instance: echarts.ECharts | null = null;
  let resizeObserver: ResizeObserver | null = null;

  function initChart(options: EChartsOption) {
    if (!chartRef.value) return;

    // Dispose existing instance if theme changed
    if (instance) {
      instance.dispose();
      instance = null;
    }

    const theme = darkMode.value ? 'dark' : undefined;
    instance = echarts.init(chartRef.value, theme);
    instance.setOption(options, true);
  }

  function updateOption(options: EChartsOption, notMerge = false) {
    if (!instance) return;
    instance.setOption(options, { notMerge, lazyUpdate: true });
  }

  function resize() {
    instance?.resize();
  }

  function dispose() {
    resizeObserver?.disconnect();
    resizeObserver = null;
    instance?.dispose();
    instance = null;
  }

  onMounted(() => {
    if (chartRef.value) {
      resizeObserver = new ResizeObserver(() => {
        instance?.resize();
      });
      resizeObserver.observe(chartRef.value);
    }
  });

  onUnmounted(() => {
    dispose();
  });

  return {
    chartRef,
    initChart,
    updateOption,
    resize,
    dispose,
    getInstance: () => instance,
  };
}
