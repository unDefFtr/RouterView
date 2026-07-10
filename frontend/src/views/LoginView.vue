<script setup lang="ts">
import { computed, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import AuthShell from '@/components/auth/AuthShell.vue';
import FeatherIcon from '@/components/shared/FeatherIcon.vue';
import { ApiError } from '@/api';
import { useAuthStore } from '@/stores/auth';

const auth = useAuthStore();
const route = useRoute();
const router = useRouter();
const username = ref('admin');
const password = ref('');
const submitting = ref(false);
const errorMessage = ref('');
const showPassword = ref(false);
const canSubmit = computed(() => username.value.trim().length > 0 && password.value.length > 0);

function safeRedirect(): string {
  const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/';
  return redirect.startsWith('/') && !redirect.startsWith('//') ? redirect : '/';
}

async function submit(): Promise<void> {
  if (!canSubmit.value || submitting.value) return;
  submitting.value = true;
  errorMessage.value = '';
  try {
    await auth.login(username.value, password.value);
    await router.replace(safeRedirect());
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) errorMessage.value = '用户名或密码错误';
    else if (error instanceof ApiError && error.status === 429) errorMessage.value = '尝试次数过多，请稍后再试';
    else errorMessage.value = error instanceof Error ? error.message : '登录失败';
  } finally {
    password.value = '';
    submitting.value = false;
  }
}
</script>

<template>
  <AuthShell title="管理员登录" subtitle="使用 RouterView 管理员凭据继续。" icon="lock">
    <form class="auth-form" @submit.prevent="submit">
      <label for="login-username">用户名</label>
      <input id="login-username" v-model="username" autocomplete="username" autofocus />

      <label for="login-password">密码</label>
      <div class="password-control">
        <input
          id="login-password"
          v-model="password"
          :type="showPassword ? 'text' : 'password'"
          autocomplete="current-password"
        />
        <button
          type="button"
          :aria-label="showPassword ? '隐藏密码' : '显示密码'"
          :title="showPassword ? '隐藏密码' : '显示密码'"
          @click="showPassword = !showPassword"
        >
          <FeatherIcon :name="showPassword ? 'eye-off' : 'eye'" :size="16" />
        </button>
      </div>

      <p v-if="errorMessage" class="form-error" role="alert">{{ errorMessage }}</p>
      <button class="primary-button" type="submit" :disabled="!canSubmit || submitting">
        <span v-if="submitting" class="button-spinner" />
        <FeatherIcon v-else name="log-in" :size="16" />
        {{ submitting ? '登录中...' : '登录' }}
      </button>
    </form>

    <template #footer>
      固定设备可使用 <RouterLink to="/pair">配对码登录</RouterLink>
    </template>
  </AuthShell>
</template>

<style scoped>
.auth-form { display: grid; gap: 9px; }
label { color: var(--color-text-secondary); font-size: 0.78rem; font-weight: 600; }
input {
  width: 100%; height: 42px; border: 1px solid var(--color-border); border-radius: var(--border-radius-sm);
  background: var(--color-bg-input); color: var(--color-text-primary); padding: 0 12px; font: inherit;
}
.password-control { position: relative; }
.password-control input { padding-right: 44px; }
.password-control button {
  position: absolute; right: 4px; top: 4px; width: 34px; height: 34px; display: grid; place-items: center;
  border: 0; border-radius: var(--border-radius-sm); background: transparent; color: var(--color-text-secondary); cursor: pointer;
}
.primary-button {
  height: 42px; margin-top: 12px; border: 0; border-radius: var(--border-radius-sm); background: var(--color-accent);
  color: var(--color-text-inverse); display: flex; align-items: center; justify-content: center; gap: 8px; font: inherit; font-weight: 600; cursor: pointer;
}
.primary-button:disabled { opacity: 0.55; cursor: not-allowed; }
.form-error { color: var(--color-danger); background: var(--color-danger-subtle); padding: 8px 10px; border-radius: var(--border-radius-sm); font-size: 0.78rem; }
.button-spinner { width: 15px; height: 15px; border: 2px solid currentColor; border-right-color: transparent; border-radius: 50%; animation: spin 0.7s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
@media (max-height: 520px) and (min-width: 600px) {
  .auth-form { gap: 5px; }
  input { height: 36px; }
  .password-control button { width: 28px; height: 28px; }
  .primary-button { height: 36px; margin-top: 4px; }
}
</style>
