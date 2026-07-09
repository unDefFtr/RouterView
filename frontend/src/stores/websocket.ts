import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { ConnectionState } from '@/types/ws';
import type { WsServerMessage } from '@/types/ws';
import { useDashboardStore } from './dashboard';

/**
 * WebSocket connection management store.
 * Handles connect, disconnect, reconnect with exponential backoff.
 */
export const useWebSocketStore = defineStore('websocket', () => {
  const connectionState = ref<ConnectionState>('disconnected');
  const reconnectAttempt = ref(0);
  const maxReconnectAttempts = 10;
  const reconnectBaseMs = 1000;
  const maxReconnectMs = 30000;

  let ws: WebSocket | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let intentionalDisconnect = false;

  function connect(url: string) {
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    intentionalDisconnect = false;
    connectionState.value = 'connecting';

    try {
      ws = new WebSocket(url);
    } catch (e) {
      console.error('[WS] Failed to create WebSocket:', e);
      scheduleReconnect(url);
      return;
    }

    ws.onopen = () => {
      console.log('[WS] Connected');
      connectionState.value = 'connected';
      reconnectAttempt.value = 0;

      const dashboardStore = useDashboardStore();
      dashboardStore.wsConnected = true;
    };

    ws.onmessage = (event) => {
      try {
        const msg: WsServerMessage = JSON.parse(event.data);
        handleMessage(msg);
      } catch (e) {
        console.error('[WS] Failed to parse message:', e);
      }
    };

    ws.onclose = (event) => {
      console.log(`[WS] Disconnected (code: ${event.code}, reason: ${event.reason})`);
      connectionState.value = 'disconnected';

      const dashboardStore = useDashboardStore();
      dashboardStore.wsConnected = false;

      if (!intentionalDisconnect) {
        scheduleReconnect(url);
      }
    };

    ws.onerror = (event) => {
      console.error('[WS] Error:', event);
    };
  }

  function disconnect() {
    intentionalDisconnect = true;
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    if (ws) {
      ws.close(1000, 'Client disconnect');
      ws = null;
    }
    connectionState.value = 'disconnected';

    const dashboardStore = useDashboardStore();
    dashboardStore.wsConnected = false;
  }

  function scheduleReconnect(url: string) {
    if (reconnectAttempt.value >= maxReconnectAttempts) {
      console.warn('[WS] Max reconnect attempts reached');
      return;
    }

    const delay = Math.min(
      reconnectBaseMs * Math.pow(2, reconnectAttempt.value),
      maxReconnectMs
    );

    console.log(`[WS] Reconnecting in ${delay}ms (attempt ${reconnectAttempt.value + 1}/${maxReconnectAttempts})`);

    reconnectTimer = setTimeout(() => {
      reconnectAttempt.value++;
      connect(url);
    }, delay);
  }

  function handleMessage(msg: WsServerMessage) {
    const dashboardStore = useDashboardStore();

    switch (msg.type) {
      case 'snapshot':
        dashboardStore.handleSnapshot(msg.data);
        break;
      case 'update':
        dashboardStore.handleUpdate(msg.data);
        break;
      case 'connection_status':
        dashboardStore.handleConnectionStatus(msg.connected, msg.lastPoll);
        break;
      default:
        console.warn('[WS] Unknown message type:', (msg as any).type);
    }
  }

  return {
    connectionState,
    reconnectAttempt,
    connect,
    disconnect,
  };
});
