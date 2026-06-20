<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useThemeStore, type ThemePreference } from '@/stores/theme';
import { useDashboardStore } from '@/stores/dashboard';
import { useViewport } from '@/composables/useViewport';
import FeatherIcon from '@/components/shared/FeatherIcon.vue';
import {
  fetchFullConfig,
  fetchHealth,
  updateConfig,
  testConnection,
  type FullConfig,
  type HealthResponse,
} from '@/api';

const themeStore = useThemeStore();
const dashboardStore = useDashboardStore();
const { isPortrait } = useViewport();

// ── Connection status ─────────────────────────────────────

const health = ref<HealthResponse | null>(null);
const routerosConnected = ref(false);

async function loadHealth() {
  try {
    health.value = await fetchHealth();
  } catch { /* ignore */ }
}

// ── Config state ──────────────────────────────────────────

const config = ref<FullConfig | null>(null);
const configLoading = ref(true);
const configError = ref<string | null>(null);
const showPassword = ref(false);

async function loadConfig() {
  configLoading.value = true;
  configError.value = null;
  try {
    config.value = await fetchFullConfig();
  } catch (e: any) {
    configError.value = e.message || '加载配置失败';
  } finally {
    configLoading.value = false;
  }
}

// ── Field-level save feedback ─────────────────────────────

const saveStatus = ref<Record<string, 'saving' | 'saved' | 'error'>>({});

async function saveField(key: string, value: unknown) {
  saveStatus.value[key] = 'saving';
  try {
    const result = await updateConfig({ [key]: value });
    // Check if restart was required
    if (result.requires_restart.includes(key)) {
      saveStatus.value[key] = 'saved';
    } else {
      saveStatus.value[key] = 'saved';
    }
    // Clear status after 2s
    setTimeout(() => {
      if (saveStatus.value[key] === 'saved') {
        delete saveStatus.value[key];
      }
    }, 2000);
  } catch {
    saveStatus.value[key] = 'error';
  }
}

// ── Theme ─────────────────────────────────────────────────

function onThemeChange(pref: ThemePreference) {
  themeStore.setPreference(pref);
  if (config.value) {
    config.value.theme = pref;
    saveField('theme', pref);
  }
}

// ── RouterOS connection test ──────────────────────────────

const testing = ref(false);
const testResult = ref<{ success: boolean; model?: string; version?: string; error?: string } | null>(null);

async function runConnectionTest() {
  testing.value = true;
  testResult.value = null;
  try {
    // Send the current form values so the backend tests with what the user typed
    testResult.value = await testConnection({
      routeros_host: config.value?.routeros_host,
      routeros_port: config.value?.routeros_port,
      routeros_scheme: config.value?.routeros_scheme,
      accept_invalid_certs: config.value?.accept_invalid_certs,
    });
  } catch (e: any) {
    testResult.value = { success: false, error: e.message };
  } finally {
    testing.value = false;
  }
}

// ── Debounced save for number inputs ──────────────────────

let debounceTimers: Record<string, ReturnType<typeof setTimeout>> = {};

function debounceSave(key: string, value: unknown, ms = 600) {
  if (debounceTimers[key]) clearTimeout(debounceTimers[key]);
  debounceTimers[key] = setTimeout(() => saveField(key, value), ms);
}

// ── Lifecycle ─────────────────────────────────────────────

onMounted(() => {
  loadHealth();
  loadConfig();
  routerosConnected.value = dashboardStore.routerosConnected;
});
</script>

<template>
  <div class="settings-view">
    <div class="settings-scroll">
      <h1 class="settings-page-title">设置</h1>

      <div class="settings-grid" :class="{ portrait: isPortrait }">
        <div class="settings-col">

      <!-- ═══════ Section 1: Connection Status ═══════ -->
      <section class="settings-section">
        <div class="section-header">
          <FeatherIcon name="activity" :size="16" />
          <h2>连接状态</h2>
        </div>
        <div class="status-grid">
          <div class="status-item">
            <span class="status-label">RouterOS</span>
            <span class="status-value">
              <span
                class="status-dot"
                :class="routerosConnected ? 'online' : 'offline'"
              />
              {{ routerosConnected ? '已连接' : '未连接' }}
            </span>
          </div>
          <div class="status-item">
            <span class="status-label">WebSocket 连接数</span>
            <span class="status-value mono">{{ health?.ws_connections ?? '—' }}</span>
          </div>
          <div class="status-item">
            <span class="status-label">后端版本</span>
            <span class="status-value mono">{{ health?.version ?? '—' }}</span>
          </div>
        </div>
      </section>

      <!-- ═══════ Section 2: Theme ═══════ -->
      <section class="settings-section">
        <div class="section-header">
          <FeatherIcon name="sun" :size="16" />
          <h2>主题</h2>
        </div>
        <div class="theme-options">
          <label
            v-for="opt in [
              { value: 'system' as ThemePreference, label: '跟随系统', desc: '自动匹配系统亮暗模式', icon: 'monitor' },
              { value: 'dark' as ThemePreference, label: '暗色', desc: '深色界面，适合低光环境', icon: 'moon' },
              { value: 'light' as ThemePreference, label: '亮色', desc: '浅色界面，适合明亮环境', icon: 'sun' },
            ]"
            :key="opt.value"
            class="theme-option"
            :class="{ active: themeStore.preference === opt.value }"
          >
            <input
              type="radio"
              name="theme"
              :value="opt.value"
              :checked="themeStore.preference === opt.value"
              @change="onThemeChange(opt.value)"
            />
            <div class="theme-option-content">
              <div class="theme-option-header">
                <FeatherIcon :name="opt.icon" :size="16" />
                <span class="theme-option-label">{{ opt.label }}</span>
              </div>
              <span class="theme-option-desc">{{ opt.desc }}</span>
            </div>
          </label>
        </div>
      </section>

        </div>
        <div class="settings-col">

      <!-- ═══════ Section 3: RouterOS Connection ═══════ -->
      <section class="settings-section">
        <div class="section-header">
          <FeatherIcon name="server" :size="16" />
          <h2>RouterOS 连接</h2>
          <span v-if="configLoading" class="section-hint">加载中...</span>
          <span v-else-if="configError" class="section-hint error">{{ configError }}</span>
        </div>

        <template v-if="config">
          <div class="field-group">
            <div class="field">
              <label class="field-label">主机地址</label>
              <div class="field-control">
                <input
                  class="field-input mono"
                  type="text"
                  :value="config.routeros_host"
                  @change="(e: any) => { config!.routeros_host = e.target.value; saveField('routeros_host', e.target.value) }"
                />
                <span v-if="saveStatus['routeros_host'] === 'saved'" class="save-badge">已保存</span>
                <span v-if="saveStatus['routeros_host'] === 'error'" class="save-badge error">失败</span>
              </div>
              <span class="field-hint">修改后自动重连，即时生效</span>
            </div>

            <div class="field">
              <label class="field-label">端口</label>
              <div class="field-control">
                <input
                  class="field-input mono short"
                  type="number"
                  :value="config.routeros_port"
                  @change="(e: any) => { config!.routeros_port = parseInt(e.target.value) || 443; saveField('routeros_port', config!.routeros_port) }"
                />
                <span v-if="saveStatus['routeros_port'] === 'saved'" class="save-badge">已保存</span>
              </div>
            </div>

            <div class="field">
              <label class="field-label">连接方式</label>
              <div class="field-control">
                <select
                  class="field-input"
                  :value="config.routeros_scheme"
                  @change="(e: any) => { config!.routeros_scheme = e.target.value; saveField('routeros_scheme', e.target.value) }"
                >
                  <option value="https">HTTPS (推荐)</option>
                  <option value="http">HTTP</option>
                </select>
              </div>
            </div>

            <div class="field">
              <label class="field-label">用户名</label>
              <div class="field-control">
                <input
                  class="field-input"
                  type="text"
                  :value="config.routeros_username"
                  placeholder="admin"
                  @change="(e: any) => { config!.routeros_username = e.target.value; saveField('routeros_username', e.target.value) }"
                />
                <span v-if="saveStatus['routeros_username'] === 'saved'" class="save-badge">已保存</span>
              </div>
            </div>

            <div class="field">
              <label class="field-label">密码</label>
              <div class="field-control">
                <input
                  class="field-input mono"
                  :type="showPassword ? 'text' : 'password'"
                  placeholder="留空表示未设置"
                  @change="(e: any) => { saveField('routeros_password', e.target.value || '') }"
                />
                <button
                  type="button"
                  class="toggle-vis-btn"
                  @click="showPassword = !showPassword"
                  :title="showPassword ? '隐藏密码' : '显示密码'"
                >
                  <FeatherIcon :name="showPassword ? 'eye-off' : 'eye'" :size="14" />
                </button>
                <span v-if="config.routeros_password" class="save-badge saved-hint">已设置</span>
              </div>
            </div>

            <div class="field checkbox-field">
              <label class="field-label">允许自签证书</label>
              <div class="field-control">
                <label class="toggle">
                  <input
                    type="checkbox"
                    :checked="config.accept_invalid_certs"
                    @change="(e: any) => { config!.accept_invalid_certs = e.target.checked; saveField('accept_invalid_certs', e.target.checked) }"
                  />
                  <span class="toggle-slider" />
                </label>
              </div>
            </div>
          </div>

          <!-- Connection test -->
          <div class="action-row">
            <button class="btn-secondary" :disabled="testing" @click="runConnectionTest">
              <span v-if="testing" class="spinner-sm" />
              <span>{{ testing ? '测试中...' : '测试连接' }}</span>
            </button>
            <div v-if="testResult" class="test-result" :class="{ success: testResult.success, fail: !testResult.success }">
              <template v-if="testResult.success">
                <FeatherIcon name="check-circle" :size="14" />
                <span>连接成功 — {{ testResult.model || 'RouterOS' }} {{ testResult.version || '' }}</span>
              </template>
              <template v-else>
                <FeatherIcon name="x-circle" :size="14" />
                <span>{{ testResult.error || '连接失败' }}</span>
              </template>
            </div>
          </div>
        </template>
      </section>

      <!-- ═══════ Section 4: Polling & Retention ═══════ -->
      <section class="settings-section">
        <div class="section-header">
          <FeatherIcon name="clock" :size="16" />
          <h2>轮询与数据保留</h2>
        </div>

        <template v-if="config">
          <div class="field-group">
            <div class="field">
              <label class="field-label">主轮询间隔 (秒)</label>
              <div class="field-control">
                <input
                  class="field-input mono short"
                  type="number"
                  min="1"
                  max="30"
                  :value="config.poll_interval_secs"
                  @input="(e: any) => { const v = parseInt(e.target.value) || 3; config!.poll_interval_secs = v; debounceSave('poll_interval_secs', v) }"
                />
                <span v-if="saveStatus['poll_interval_secs'] === 'saving'" class="save-badge saving">保存中</span>
                <span v-if="saveStatus['poll_interval_secs'] === 'saved'" class="save-badge">已保存 — 即时生效</span>
                <span v-if="saveStatus['poll_interval_secs'] === 'error'" class="save-badge error">失败</span>
              </div>
              <span class="field-hint">数据采集频率，1–30 秒。越低越实时但 RouterOS 负载更大。</span>
            </div>

            <div class="field">
              <label class="field-label">延迟探测间隔 (秒)</label>
              <div class="field-control">
                <input
                  class="field-input mono short"
                  type="number"
                  min="10"
                  max="600"
                  :value="config.probe_interval_secs"
                  @input="(e: any) => { const v = parseInt(e.target.value) || 60; config!.probe_interval_secs = v; debounceSave('probe_interval_secs', v) }"
                />
                <span v-if="saveStatus['probe_interval_secs'] === 'saved'" class="save-badge">已保存 — 即时生效</span>
              </div>
              <span class="field-hint">Ping 探测 ISP / DNS / CDN 的间隔，10–600 秒。</span>
            </div>

            <div class="field">
              <label class="field-label">原始数据保留 (天)</label>
              <div class="field-control">
                <input
                  class="field-input mono short"
                  type="number"
                  min="1"
                  max="30"
                  :value="config.db_raw_retention_days"
                  @input="(e: any) => { const v = parseInt(e.target.value) || 7; config!.db_raw_retention_days = v; debounceSave('db_raw_retention_days', v) }"
                />
                <span v-if="saveStatus['db_raw_retention_days'] === 'saved'" class="save-badge">已保存</span>
              </div>
              <span class="field-hint">高精度数据（每 5 秒采样）的保留天数，超期后聚合为分钟级。</span>
            </div>

            <div class="field">
              <label class="field-label">聚合数据保留 (天)</label>
              <div class="field-control">
                <input
                  class="field-input mono short"
                  type="number"
                  min="7"
                  max="365"
                  :value="config.db_total_retention_days"
                  @input="(e: any) => { const v = parseInt(e.target.value) || 90; config!.db_total_retention_days = v; debounceSave('db_total_retention_days', v) }"
                />
                <span v-if="saveStatus['db_total_retention_days'] === 'saved'" class="save-badge">已保存</span>
              </div>
              <span class="field-hint">所有聚合数据的最大保留天数，超期后自动清理。</span>
            </div>
          </div>
        </template>
      </section>

        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.settings-view {
  height: calc(100vh - var(--navbar-height));
  overflow: hidden;
}

.settings-scroll {
  height: 100%;
  overflow-y: auto;
  padding: var(--content-gap);
  padding-bottom: calc(var(--content-gap) + var(--bottom-bar-height, 0px));
}

.settings-page-title {
  font-size: 1.3rem;
  font-weight: 700;
  color: var(--color-text-primary);
  margin-bottom: 20px;
}

/* ── Two-column grid (landscape only) ────────────────── */

.settings-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--content-gap);
  align-items: start;
}

.settings-grid.portrait {
  grid-template-columns: 1fr;
}

.settings-col {
  display: flex;
  flex-direction: column;
  gap: 16px;
  min-width: 0;
}

/* ── Section ─────────────────────────────────────────── */

.settings-section {
  background: var(--color-bg-card);
  border: 1px solid var(--color-border-light);
  border-radius: var(--card-radius);
  padding: var(--card-padding);
}

.section-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 16px;
  color: var(--color-text-secondary);
}

.section-header h2 {
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--color-text-primary);
  margin: 0;
}

.section-hint {
  font-size: 0.72rem;
  color: var(--color-text-muted);
  margin-left: auto;
}

.section-hint.error {
  color: var(--color-danger);
}

/* ── Status Grid ─────────────────────────────────────── */

.status-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 12px;
}

.status-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 8px 12px;
  background: var(--color-bg-input);
  border-radius: var(--border-radius-sm);
}

.status-label {
  font-size: 0.68rem;
  color: var(--color-text-muted);
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.status-value {
  font-size: 0.88rem;
  font-weight: 500;
  color: var(--color-text-primary);
  display: flex;
  align-items: center;
  gap: 6px;
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.status-dot.online { background: var(--color-success); }
.status-dot.offline { background: var(--color-danger); }

/* ── Theme Options ────────────────────────────────────── */

.theme-options {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.theme-option {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 14px;
  border: 1px solid var(--color-border-light);
  border-radius: var(--border-radius-sm);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.theme-option:hover {
  background: var(--color-bg-hover);
}

.theme-option.active {
  border-color: var(--color-accent-border);
  background: var(--color-accent-subtle);
}

.theme-option input { display: none; }

.theme-option-content {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.theme-option-header {
  display: flex;
  align-items: center;
  gap: 6px;
}

.theme-option-label {
  font-size: 0.9rem;
  font-weight: 500;
  color: var(--color-text-primary);
}

.theme-option-desc {
  font-size: 0.72rem;
  color: var(--color-text-muted);
}

/* ── Field Groups ─────────────────────────────────────── */

.field-group {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.field-label {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--color-text-secondary);
}

.field-control {
  display: flex;
  align-items: center;
  gap: 10px;
}

.field-input {
  padding: 7px 12px;
  font-size: 0.85rem;
  font-family: var(--font-sans);
  border: 1px solid var(--color-border-light);
  border-radius: var(--border-radius-sm);
  background: var(--color-bg-input);
  color: var(--color-text-primary);
  outline: none;
  transition: border-color var(--transition-fast);
  flex: 1;
  max-width: 320px;
}

.field-input.short {
  max-width: 100px;
}

.field-input:focus {
  border-color: var(--color-accent);
}

.field-hint {
  font-size: 0.68rem;
  color: var(--color-text-muted);
}

.restart-hint {
  display: flex;
  align-items: center;
  gap: 4px;
  color: var(--color-warning, #f59e0b);
}

/* ── Toggle switch ────────────────────────────────────── */

.toggle {
  position: relative;
  display: inline-block;
  width: 40px;
  height: 22px;
  cursor: pointer;
}

.toggle input {
  display: none;
}

.toggle-slider {
  position: absolute;
  inset: 0;
  background: var(--color-bg-hover);
  border-radius: 11px;
  transition: background var(--transition-fast);
}

.toggle-slider::after {
  content: '';
  position: absolute;
  top: 3px;
  left: 3px;
  width: 16px;
  height: 16px;
  background: var(--color-text-muted);
  border-radius: 50%;
  transition: all var(--transition-fast);
}

.toggle input:checked + .toggle-slider {
  background: var(--color-accent);
}

.toggle input:checked + .toggle-slider::after {
  left: 21px;
  background: #fff;
}

/* ── Save badge ───────────────────────────────────────── */

.save-badge {
  font-size: 0.7rem;
  padding: 2px 8px;
  border-radius: 100px;
  background: var(--color-success-subtle);
  color: var(--color-success);
  white-space: nowrap;
  flex-shrink: 0;
}

.save-badge.saving {
  background: var(--color-bg-hover);
  color: var(--color-text-muted);
}

.save-badge.error {
  background: var(--color-danger-subtle);
  color: var(--color-danger);
}

.save-badge.saved-hint {
  background: transparent;
  color: var(--color-text-muted);
  font-size: 0.68rem;
}

/* ── Password visibility toggle ─────────────────────── */

.toggle-vis-btn {
  width: 32px;
  height: 32px;
  aspect-ratio: 1;
  flex-shrink: 0;
  border: 1px solid var(--color-border-light);
  border-radius: var(--border-radius-sm);
  background: var(--color-bg-elevated, var(--color-bg-input));
  color: var(--color-text-muted);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  transition: all var(--transition-fast);
}

.toggle-vis-btn:hover {
  background: var(--color-bg-hover);
  color: var(--color-text-secondary);
}

/* ── Action row ───────────────────────────────────────── */

.action-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 12px;
  flex-wrap: wrap;
}

.btn-secondary {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 7px 16px;
  font-size: 0.85rem;
  font-weight: 500;
  font-family: var(--font-sans);
  border: 1px solid var(--color-border);
  border-radius: var(--border-radius-sm);
  background: var(--color-bg-elevated, var(--color-bg-input));
  color: var(--color-text-primary);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.btn-secondary:hover:not(:disabled) {
  background: var(--color-bg-hover);
}

.btn-secondary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.test-result {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.8rem;
  padding: 6px 10px;
  border-radius: var(--border-radius-sm);
}

.test-result.success {
  color: var(--color-success);
  background: var(--color-success-subtle);
}

.test-result.fail {
  color: var(--color-danger);
  background: var(--color-danger-subtle);
}

.spinner-sm {
  width: 14px;
  height: 14px;
  border: 2px solid var(--color-border-light);
  border-top-color: var(--color-accent);
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

/* ── Responsive ───────────────────────────────────────── */

@media (orientation: portrait) {
  .status-grid {
    grid-template-columns: 1fr 1fr;
  }
  .settings-scroll {
    padding-bottom: calc(var(--content-gap) + var(--bottom-bar-height, 56px));
  }
}
</style>
