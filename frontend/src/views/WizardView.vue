<script setup lang="ts">
import { ref, reactive, computed } from 'vue';
import { useRouter } from 'vue-router';
import { useThemeStore, type ThemePreference } from '@/stores/theme';
import { useViewport } from '@/composables/useViewport';
import FeatherIcon from '@/components/shared/FeatherIcon.vue';
import {
  updateConfig,
  testConnection,
  type ConnectionTestResult,
} from '@/api';

const router = useRouter();
const themeStore = useThemeStore();
const { isPortrait } = useViewport();

// ── Steps ───────────────────────────────────────────────

const currentStep = ref(1);
const totalSteps = 3;

const stepTitles = ['RouterOS 连接', '偏好设置', '完成配置'];

function nextStep() {
  if (currentStep.value < totalSteps) {
    currentStep.value++;
  }
}

function prevStep() {
  if (currentStep.value > 1) {
    currentStep.value--;
  }
}

// ── Form state ──────────────────────────────────────────

const form = reactive({
  routeros_host: '192.168.88.1',
  routeros_port: 443,
  routeros_scheme: 'https' as 'http' | 'https',
  routeros_username: 'admin',
  routeros_password: '',
  accept_invalid_certs: false,
  poll_interval_secs: 3,
  theme: 'system' as ThemePreference,
});

// ── Connection test ─────────────────────────────────────

const testing = ref(false);
const testResult = ref<ConnectionTestResult | null>(null);
const connectionVerified = ref(false);

async function runConnectionTest() {
  testing.value = true;
  testResult.value = null;
  connectionVerified.value = false;
  try {
    testResult.value = await testConnection({
      routeros_host: form.routeros_host,
      routeros_port: form.routeros_port,
      routeros_scheme: form.routeros_scheme,
      routeros_username: form.routeros_username,
      routeros_password: form.routeros_password || '',
      accept_invalid_certs: form.accept_invalid_certs,
    });
    connectionVerified.value = testResult.value.success;
  } catch (e: any) {
    testResult.value = { success: false, error: e.message };
  } finally {
    testing.value = false;
  }
}

// ── Password visibility ─────────────────────────────────

const showPassword = ref(false);

// ── Theme options ───────────────────────────────────────

const themeOptions: { value: ThemePreference; label: string; desc: string }[] = [
  { value: 'system', label: '💻 跟随系统', desc: '自动匹配系统亮暗模式' },
  { value: 'dark', label: '🌙 暗色', desc: '深色界面，适合低光环境' },
  { value: 'light', label: '☀️ 亮色', desc: '浅色界面，适合明亮环境' },
];

function onThemeChange(pref: ThemePreference) {
  form.theme = pref;
  themeStore.setPreference(pref);
}

// ── Save & finish ───────────────────────────────────────

const saving = ref(false);
const saveError = ref<string | null>(null);
const saveDone = ref(false);

async function finishWizard() {
  saving.value = true;
  saveError.value = null;
  try {
    // Save all config fields + mark wizard as completed
    await updateConfig({
      routeros_host: form.routeros_host,
      routeros_port: form.routeros_port,
      routeros_scheme: form.routeros_scheme,
      routeros_username: form.routeros_username,
      routeros_password: form.routeros_password,
      accept_invalid_certs: form.accept_invalid_certs,
      poll_interval_secs: form.poll_interval_secs,
      theme: form.theme,
      wizard_completed: 'true',
    });
    saveDone.value = true;
    // Auto-navigate to dashboard after a brief pause
    setTimeout(() => {
      router.push('/');
    }, 1500);
  } catch (e: any) {
    saveError.value = e.message || '保存配置失败';
  } finally {
    saving.value = false;
  }
}

// ── Step 1 validation ───────────────────────────────────

const canProceedFromStep1 = computed(() => connectionVerified.value);
</script>

<template>
  <div class="wizard-view" :class="{ portrait: isPortrait }">
    <!-- Background decoration -->
    <div class="wizard-bg" />

    <div class="wizard-card">
      <!-- Header -->
      <div class="wizard-header">
        <div class="wizard-brand">
          <span class="brand-icon">📡</span>
          <span class="brand-name">RouterView</span>
        </div>
        <h1 class="wizard-title">欢迎使用 RouterView</h1>
        <p class="wizard-subtitle">
          在开始之前，请配置 RouterOS 连接信息以启用网络监控。
        </p>
      </div>

      <!-- Step indicator -->
      <div class="step-indicator">
        <div
          v-for="step in totalSteps"
          :key="step"
          class="step-dot-row"
        >
          <div
            class="step-dot"
            :class="{
              active: currentStep === step,
              done: currentStep > step,
            }"
          >
            <span v-if="currentStep > step" class="step-check">✓</span>
            <span v-else>{{ step }}</span>
          </div>
          <span
            class="step-label"
            :class="{ active: currentStep === step, done: currentStep > step }"
          >
            {{ stepTitles[step - 1] }}
          </span>
          <div v-if="step < totalSteps" class="step-line" :class="{ done: currentStep > step }" />
        </div>
      </div>

      <!-- ═══════ Step 1: RouterOS Connection ═══════ -->
      <div v-if="currentStep === 1" class="wizard-body">
        <section class="wizard-section">
          <div class="section-header">
            <FeatherIcon name="server" :size="16" />
            <h2>RouterOS 连接信息</h2>
          </div>

          <div class="field-group">
            <div class="field">
              <label class="field-label">主机地址</label>
              <input
                v-model="form.routeros_host"
                class="field-input mono"
                type="text"
                placeholder="192.168.88.1"
              />
            </div>

            <div class="field-row">
              <div class="field" style="flex: 1">
                <label class="field-label">端口</label>
                <input
                  v-model.number="form.routeros_port"
                  class="field-input mono short"
                  type="number"
                />
              </div>
              <div class="field" style="flex: 2">
                <label class="field-label">连接方式</label>
                <select v-model="form.routeros_scheme" class="field-input">
                  <option value="https">HTTPS (推荐)</option>
                  <option value="http">HTTP</option>
                </select>
              </div>
            </div>

            <div class="field">
              <label class="field-label">用户名</label>
              <input
                v-model="form.routeros_username"
                class="field-input"
                type="text"
                placeholder="admin"
              />
            </div>

            <div class="field">
              <label class="field-label">密码</label>
              <div class="field-control">
                <input
                  v-model="form.routeros_password"
                  class="field-input mono"
                  :type="showPassword ? 'text' : 'password'"
                  placeholder="输入 RouterOS 密码"
                />
                <button
                  type="button"
                  class="toggle-vis-btn"
                  @click="showPassword = !showPassword"
                  :title="showPassword ? '隐藏密码' : '显示密码'"
                >
                  <FeatherIcon :name="showPassword ? 'eye-off' : 'eye'" :size="14" />
                </button>
              </div>
            </div>

            <div class="field checkbox-field">
              <label class="field-label">允许自签证书</label>
              <div class="field-control">
                <label class="toggle">
                  <input v-model="form.accept_invalid_certs" type="checkbox" />
                  <span class="toggle-slider" />
                </label>
                <span class="field-hint-inline">仅 HTTPS 时需要，用于自签名证书</span>
              </div>
            </div>
          </div>

          <!-- Connection test -->
          <div class="test-section">
            <button
              class="btn-test"
              :disabled="testing"
              @click="runConnectionTest"
            >
              <span v-if="testing" class="spinner-sm" />
              <FeatherIcon v-else name="zap" :size="14" />
              <span>{{ testing ? '测试中...' : '测试连接' }}</span>
            </button>

            <div
              v-if="testResult"
              class="test-result"
              :class="{ success: testResult.success, fail: !testResult.success }"
            >
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
        </section>
      </div>

      <!-- ═══════ Step 2: Preferences ═══════ -->
      <div v-if="currentStep === 2" class="wizard-body">
        <section class="wizard-section">
          <div class="section-header">
            <FeatherIcon name="sliders" :size="16" />
            <h2>偏好设置</h2>
          </div>

          <div class="field-group">
            <div class="field">
              <label class="field-label">轮询间隔 (秒)</label>
              <input
                v-model.number="form.poll_interval_secs"
                class="field-input mono short"
                type="number"
                min="1"
                max="30"
              />
              <span class="field-hint">数据采集频率，1–30 秒。越低越实时但 RouterOS 负载更大。</span>
            </div>
          </div>
        </section>

        <section class="wizard-section">
          <div class="section-header">
            <FeatherIcon name="sun" :size="16" />
            <h2>主题</h2>
          </div>

          <div class="theme-options">
            <label
              v-for="opt in themeOptions"
              :key="opt.value"
              class="theme-option"
              :class="{ active: form.theme === opt.value }"
            >
              <input
                type="radio"
                name="wizard-theme"
                :value="opt.value"
                :checked="form.theme === opt.value"
                @change="onThemeChange(opt.value)"
              />
              <div class="theme-option-content">
                <span class="theme-option-label">{{ opt.label }}</span>
                <span class="theme-option-desc">{{ opt.desc }}</span>
              </div>
            </label>
          </div>
        </section>
      </div>

      <!-- ═══════ Step 3: Complete ═══════ -->
      <div v-if="currentStep === 3" class="wizard-body">
        <section class="wizard-section">
          <div class="section-header">
            <FeatherIcon name="check-circle" :size="16" />
            <h2>配置摘要</h2>
          </div>

          <div class="summary-grid">
            <div class="summary-item">
              <span class="summary-label">RouterOS 地址</span>
              <span class="summary-value mono">
                {{ form.routeros_scheme }}://{{ form.routeros_host }}:{{ form.routeros_port }}
              </span>
            </div>
            <div class="summary-item">
              <span class="summary-label">用户名</span>
              <span class="summary-value">{{ form.routeros_username }}</span>
            </div>
            <div class="summary-item">
              <span class="summary-label">密码</span>
              <span class="summary-value">{{ form.routeros_password ? '已设置' : '未设置' }}</span>
            </div>
            <div class="summary-item">
              <span class="summary-label">轮询间隔</span>
              <span class="summary-value">{{ form.poll_interval_secs }} 秒</span>
            </div>
            <div class="summary-item">
              <span class="summary-label">主题</span>
              <span class="summary-value">
                {{ themeOptions.find(o => o.value === form.theme)?.label || form.theme }}
              </span>
            </div>
          </div>

          <!-- Save result -->
          <div v-if="saveDone" class="save-success">
            <FeatherIcon name="check-circle" :size="20" />
            <span>配置已保存，正在跳转...</span>
          </div>
          <div v-else-if="saveError" class="save-fail">
            <FeatherIcon name="alert-triangle" :size="16" />
            <span>{{ saveError }}</span>
          </div>
        </section>
      </div>

      <!-- ═══════ Footer: navigation buttons ═══════ -->
      <div class="wizard-footer">
        <button
          v-if="currentStep > 1 && !saveDone"
          class="btn-secondary"
          @click="prevStep"
        >
          上一步
        </button>
        <div v-else-if="currentStep === 1" class="footer-spacer" />

        <button
          v-if="currentStep === 1"
          class="btn-primary"
          :disabled="!canProceedFromStep1"
          @click="nextStep"
        >
          下一步
        </button>

        <button
          v-if="currentStep === 2"
          class="btn-primary"
          @click="nextStep"
        >
          下一步
        </button>

        <button
          v-if="currentStep === 3 && !saveDone"
          class="btn-primary"
          :disabled="saving"
          @click="finishWizard"
        >
          <span v-if="saving" class="spinner-sm" />
          <span>{{ saving ? '保存中...' : '完成配置' }}</span>
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* ── Viewport ─────────────────────────────────────────── */

.wizard-view {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  position: relative;
  background: var(--color-bg-app);
}

.wizard-view.portrait {
  align-items: flex-start;
  padding: 16px;
}

/* ── Background decoration ────────────────────────────── */

.wizard-bg {
  position: fixed;
  inset: 0;
  pointer-events: none;
  background:
    radial-gradient(ellipse at 20% 50%, var(--color-accent-subtle, rgba(59, 130, 246, 0.04)) 0%, transparent 55%),
    radial-gradient(ellipse at 80% 20%, var(--color-accent-subtle, rgba(59, 130, 246, 0.03)) 0%, transparent 50%);
}

/* ── Card ─────────────────────────────────────────────── */

.wizard-card {
  position: relative;
  width: 100%;
  max-width: 560px;
  background: var(--color-bg-card);
  border: 1px solid var(--color-border-light);
  border-radius: var(--card-radius);
  padding: 36px 40px 28px;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08);
}

.portrait .wizard-card {
  padding: 24px 20px 20px;
}

/* ── Header ───────────────────────────────────────────── */

.wizard-header {
  text-align: center;
  margin-bottom: 28px;
}

.wizard-brand {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin-bottom: 16px;
}

.brand-icon {
  font-size: 1.5rem;
}

.brand-name {
  font-size: 1.1rem;
  font-weight: 700;
  font-family: var(--font-mono, 'JetBrains Mono', monospace);
  color: var(--color-text-primary);
}

.wizard-title {
  font-size: 1.3rem;
  font-weight: 700;
  color: var(--color-text-primary);
  margin: 0 0 8px;
}

.wizard-subtitle {
  font-size: 0.82rem;
  color: var(--color-text-muted);
  margin: 0;
  line-height: 1.5;
}

/* ── Step indicator ───────────────────────────────────── */

.step-indicator {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0;
  margin-bottom: 28px;
}

.step-dot-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.step-dot {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.8rem;
  font-weight: 600;
  flex-shrink: 0;
  border: 2px solid var(--color-border-light);
  color: var(--color-text-muted);
  background: var(--color-bg-input);
  transition: all var(--transition-fast);
}

.step-dot.active {
  border-color: var(--color-accent);
  color: var(--color-accent);
  background: var(--color-accent-subtle);
}

.step-dot.done {
  border-color: var(--color-success);
  color: var(--color-success);
  background: var(--color-success-subtle);
}

.step-check {
  font-size: 0.75rem;
  line-height: 1;
}

.step-label {
  font-size: 0.7rem;
  color: var(--color-text-muted);
  white-space: nowrap;
  transition: color var(--transition-fast);
}

.step-label.active {
  color: var(--color-accent);
  font-weight: 600;
}

.step-label.done {
  color: var(--color-success);
}

.step-line {
  width: 32px;
  height: 2px;
  background: var(--color-border-light);
  margin: 0 4px;
  flex-shrink: 0;
  border-radius: 1px;
  transition: background var(--transition-fast);
}

.step-line.done {
  background: var(--color-success);
}

.portrait .step-line {
  width: 20px;
}

/* ── Body / Sections ──────────────────────────────────── */

.wizard-body {
  min-height: 220px;
}

.wizard-section {
  margin-bottom: 20px;
}

.section-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 14px;
  color: var(--color-text-secondary);
}

.section-header h2 {
  font-size: 0.92rem;
  font-weight: 600;
  color: var(--color-text-primary);
  margin: 0;
}

/* ── Field styles (reuse SettingsView patterns) ────────── */

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

.field-row {
  display: flex;
  gap: 12px;
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
  padding: 8px 12px;
  font-size: 0.85rem;
  font-family: var(--font-sans);
  border: 1px solid var(--color-border-light);
  border-radius: var(--border-radius-sm);
  background: var(--color-bg-input);
  color: var(--color-text-primary);
  outline: none;
  transition: border-color var(--transition-fast);
  width: 100%;
  box-sizing: border-box;
}

.field-input.short {
  max-width: 110px;
}

.field-input:focus {
  border-color: var(--color-accent);
}

.field-hint {
  font-size: 0.68rem;
  color: var(--color-text-muted);
}

.field-hint-inline {
  font-size: 0.72rem;
  color: var(--color-text-muted);
}

/* ── Checkbox toggle ──────────────────────────────────── */

.checkbox-field .field-control {
  gap: 10px;
}

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

/* ── Password visibility ──────────────────────────────── */

.toggle-vis-btn {
  width: 32px;
  height: 32px;
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

/* ── Test connection ──────────────────────────────────── */

.test-section {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 16px;
  flex-wrap: wrap;
}

.btn-test {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 18px;
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

.btn-test:hover:not(:disabled) {
  background: var(--color-bg-hover);
}

.btn-test:disabled {
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

/* ── Theme options ────────────────────────────────────── */

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

.theme-option-label {
  font-size: 0.88rem;
  font-weight: 500;
  color: var(--color-text-primary);
}

.theme-option-desc {
  font-size: 0.72rem;
  color: var(--color-text-muted);
}

/* ── Summary grid ─────────────────────────────────────── */

.summary-grid {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.summary-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  background: var(--color-bg-input);
  border-radius: var(--border-radius-sm);
}

.summary-label {
  font-size: 0.75rem;
  color: var(--color-text-muted);
}

.summary-value {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--color-text-primary);
}

/* ── Save result messages ─────────────────────────────── */

.save-success {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 20px;
  padding: 12px 16px;
  border-radius: var(--border-radius-sm);
  color: var(--color-success);
  background: var(--color-success-subtle);
  font-size: 0.88rem;
  font-weight: 500;
  animation: fadeInUp 0.3s ease;
}

.save-fail {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 20px;
  padding: 12px 16px;
  border-radius: var(--border-radius-sm);
  color: var(--color-danger);
  background: var(--color-danger-subtle);
  font-size: 0.85rem;
}

@keyframes fadeInUp {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}

/* ── Footer ───────────────────────────────────────────── */

.wizard-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 24px;
  padding-top: 20px;
  border-top: 1px solid var(--color-border-light);
}

.footer-spacer {
  flex: 1;
}

.btn-secondary {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 20px;
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

.btn-secondary:hover {
  background: var(--color-bg-hover);
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 28px;
  font-size: 0.85rem;
  font-weight: 600;
  font-family: var(--font-sans);
  border: none;
  border-radius: var(--border-radius-sm);
  background: var(--color-accent);
  color: #fff;
  cursor: pointer;
  transition: all var(--transition-fast);
}

.btn-primary:hover:not(:disabled) {
  filter: brightness(1.1);
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* ── Spinner ──────────────────────────────────────────── */

.spinner-sm {
  width: 14px;
  height: 14px;
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-top-color: #fff;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}

.btn-test .spinner-sm {
  border-color: var(--color-border-light);
  border-top-color: var(--color-accent);
}

@keyframes spin {
  to { transform: rotate(360deg); }
}
</style>
