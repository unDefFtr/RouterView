// ═══════════════════════════════════════════════════════════════════
// ECharts Option Type Helpers
// ═══════════════════════════════════════════════════════════════════

import type { EChartsOption } from 'echarts';

export interface TrafficChartData {
  timestamp: string;
  download_bps: number;
  upload_bps: number;
  wan_name?: string;
}

export type TimeRange = '5M' | '1H' | '6H' | '24H' | '7D' | '30D';

export const TIME_RANGE_OPTIONS: { key: TimeRange; label: string }[] = [
  { key: '5M', label: '5分' },
  { key: '1H', label: '1时' },
  { key: '6H', label: '6时' },
];

export const HISTORY_TIME_RANGE_OPTIONS: { key: TimeRange; label: string }[] = [
  { key: '1H', label: '1小时' },
  { key: '6H', label: '6小时' },
  { key: '24H', label: '24小时' },
  { key: '7D', label: '7天' },
  { key: '30D', label: '30天' },
];

/** Map a TimeRange to its duration in milliseconds. */
export function timeRangeToMs(range: TimeRange): number {
  switch (range) {
    case '5M': return 5 * 60 * 1000;
    case '1H': return 3600 * 1000;
    case '6H': return 6 * 3600 * 1000;
    case '24H': return 24 * 3600 * 1000;
    case '7D': return 7 * 86400 * 1000;
    case '30D': return 30 * 86400 * 1000;
  }
}

/**
 * Build an ECharts option for a smooth area traffic chart.
 */
export function buildTrafficChartOption(
  points: TrafficChartData[],
  darkMode: boolean,
  timeRange: TimeRange,
  opts?: { dataZoom?: boolean },
): EChartsOption {
  const textColor = darkMode ? '#8b90a5' : '#5a6080';
  const gridColor = darkMode ? '#1e2235' : '#f1f5f9';
  const tooltipBg = darkMode ? '#1a1e2b' : '#ffffff';
  const tooltipBorder = darkMode ? '#2a2e3f' : '#e2e8f0';
  const tooltipText = darkMode ? '#e4e7f0' : '#1a1f36';

  const isLongRange = timeRange === '24H' || timeRange === '7D' || timeRange === '30D';

  const xData = points.map(p => {
    const d = new Date(p.timestamp);
    if (isLongRange) {
      // Show month-day hour:minute for longer ranges
      const datePart = d.toLocaleDateString('zh-CN', { month: '2-digit', day: '2-digit' });
      const timePart = d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
      return `${datePart} ${timePart}`;
    }
    return d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
  });

  let xInterval: number;
  if (timeRange === '5M') xInterval = Math.floor(xData.length / 6);
  else if (timeRange === '1H') xInterval = Math.floor(xData.length / 8);
  else if (timeRange === '6H') xInterval = Math.floor(xData.length / 10);
  else if (timeRange === '24H') xInterval = Math.floor(xData.length / 12);
  else if (timeRange === '7D') xInterval = Math.floor(xData.length / 14);
  else xInterval = Math.floor(xData.length / 15); // 30D

  return {
    backgroundColor: 'transparent',
    grid: {
      left: 0,
      right: 8,
      top: 12,
      bottom: opts?.dataZoom ? 36 : 0,
      containLabel: true,
    },
    dataZoom: opts?.dataZoom
      ? [
          {
            type: 'inside',
            xAxisIndex: 0,
            filterMode: 'none',
            zoomOnMouseWheel: true,
            moveOnMouseMove: true,
            minSpan: 10,
          },
          {
            type: 'slider',
            xAxisIndex: 0,
            filterMode: 'none',
            minSpan: 10,
            height: 20,
            bottom: 4,
            borderColor: gridColor,
            backgroundColor: darkMode ? '#1a1e2b' : '#ffffff',
            fillerColor: darkMode ? 'rgba(79,140,255,0.15)' : 'rgba(37,99,235,0.1)',
            handleStyle: {
              color: darkMode ? '#4f8cff' : '#2563eb',
            },
            dataBackground: {
              lineStyle: { color: gridColor },
              areaStyle: { color: 'transparent' },
            },
          },
        ]
      : undefined,
    xAxis: {
      type: 'category',
      data: xData,
      axisLine: { show: false },
      axisTick: { show: false },
      splitLine: { show: false },
      axisLabel: {
        color: textColor,
        fontSize: 10,
        rotate: isLongRange ? 30 : 0,
        interval: xInterval,
      },
    },
    yAxis: {
      type: 'value',
      splitLine: {
        lineStyle: { color: gridColor, type: 'dashed' as const },
      },
      axisLabel: {
        color: textColor,
        fontSize: 10,
        formatter: (v: number) => formatBitrateAxis(v),
      },
      splitNumber: 5,
      min: 0,
    },
    tooltip: {
      trigger: 'axis',
      backgroundColor: tooltipBg,
      borderColor: tooltipBorder,
      borderWidth: 1,
      textStyle: {
        color: tooltipText,
        fontSize: 12,
        fontFamily: "'JetBrains Mono', monospace",
      },
      formatter: (params: any) => {
        if (!Array.isArray(params)) return '';
        const time = params[0]?.axisValue || '—';
        const dl = params.find((p: any) => p.seriesName === '下载')?.value ?? 0;
        const ul = params.find((p: any) => p.seriesName === '上传')?.value ?? 0;
        return `
          <div style="font-weight:600;margin-bottom:4px">${time}</div>
          <div style="display:flex;align-items:center;gap:6px">
            <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#4f8cff"></span>
            下载 <b>${formatBitrate(dl)}</b>
          </div>
          <div style="display:flex;align-items:center;gap:6px;margin-top:2px">
            <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#22c55e"></span>
            上传 <b>${formatBitrate(ul)}</b>
          </div>
        `;
      },
    },
    series: [
      {
        name: '下载',
        type: 'line',
        smooth: 0.3,
        showSymbol: false,
        areaStyle: {
          opacity: 0.15,
          color: darkMode
            ? 'rgba(79,140,255,0.25)'
            : 'rgba(37,99,235,0.15)',
        },
        lineStyle: {
          color: darkMode ? '#4f8cff' : '#2563eb',
          width: 2,
        },
        itemStyle: {
          color: darkMode ? '#4f8cff' : '#2563eb',
        },
        data: points.map(p => p.download_bps),
        animation: false,
      },
      {
        name: '上传',
        type: 'line',
        smooth: 0.3,
        showSymbol: false,
        areaStyle: {
          opacity: 0.15,
          color: darkMode
            ? 'rgba(34,197,94,0.25)'
            : 'rgba(22,163,74,0.15)',
        },
        lineStyle: {
          color: darkMode ? '#22c55e' : '#16a34a',
          width: 2,
        },
        itemStyle: {
          color: darkMode ? '#22c55e' : '#16a34a',
        },
        data: points.map(p => p.upload_bps),
        animation: false,
      },
    ],
    legend: { show: false },
  };
}

/**
 * Format bits-per-second to human-readable string for axis labels.
 */
export function formatBitrateAxis(bps: number): string {
  if (bps === 0) return '0';
  const mbps = bps / 1_000_000;
  if (mbps >= 1) return mbps.toFixed(mbps >= 100 ? 0 : 1) + 'M';
  const kbps = bps / 1_000;
  if (kbps >= 1) return kbps.toFixed(0) + 'K';
  return bps.toFixed(0);
}

/**
 * Format bits-per-second to human-readable string for display.
 */
export function formatBitrate(bps: number): string {
  if (bps === 0) return '0 bps';
  const mbps = bps / 1_000_000;
  if (mbps >= 1) return mbps.toFixed(1) + ' Mbps';
  const kbps = bps / 1_000;
  if (kbps >= 1) return kbps.toFixed(1) + ' Kbps';
  return bps.toFixed(0) + ' bps';
}

/**
 * Format bytes to human-readable string.
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const gb = bytes / 1_000_000_000;
  if (gb >= 1) return gb.toFixed(1) + ' GB';
  const mb = bytes / 1_000_000;
  if (mb >= 1) return mb.toFixed(0) + ' MB';
  const kb = bytes / 1_000;
  if (kb >= 1) return kb.toFixed(0) + ' KB';
  return bytes.toFixed(0) + ' B';
}
