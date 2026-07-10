<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import AuthShell from '@/components/auth/AuthShell.vue';
import FeatherIcon from '@/components/shared/FeatherIcon.vue';
import { useAuthStore } from '@/stores/auth';

const auth = useAuthStore();
const router = useRouter();
const checking = ref(false);
const message = ref('');

async function retry(): Promise<void> {
  checking.value = true;
  message.value = '';
  try {
    await auth.refresh();
    if (auth.setupRequired) message.value = '初始设置尚未完成。';
    else await router.replace(auth.authenticated ? '/' : '/login');
  } catch (error) {
    message.value = error instanceof Error ? error.message : '无法连接 RouterView 后端';
  } finally {
    checking.value = false;
  }
}
</script>

<template>
  <AuthShell
    title="需要初始设置"
    subtitle="管理员凭据必须在运行 RouterView 的主机上创建。公网入口不会代理仅监听 127.0.0.1 的设置接口。"
    icon="terminal"
  >
    <div class="setup-steps">
      <p>在部署主机的终端中执行：</p>
      <pre><code>docker compose stop caddy backend
docker compose run --rm --no-deps backend admin setup admin
docker compose up -d</code></pre>
      <p>按提示输入并确认管理员密码，服务重新启动后返回此页面重试。</p>
    </div>
    <p v-if="message" class="setup-message" role="status">{{ message }}</p>
    <button type="button" :disabled="checking" @click="retry">
      <FeatherIcon name="refresh-cw" :size="16" />
      {{ checking ? '检查中...' : '重新检查' }}
    </button>
  </AuthShell>
</template>

<style scoped>
.setup-steps { display: grid; gap: 12px; color: var(--color-text-secondary); font-size: 0.82rem; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; }
.setup-message { margin-top: 14px; color: var(--color-warning); font-size: 0.8rem; }
button { width: 100%; height: 42px; margin-top: 20px; border: 0; border-radius: var(--border-radius-sm); background: var(--color-accent); color: var(--color-text-inverse); display: flex; align-items: center; justify-content: center; gap: 8px; font: inherit; font-weight: 600; cursor: pointer; }
button:disabled { opacity: 0.55; cursor: not-allowed; }
</style>
