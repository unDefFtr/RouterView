import { ref, onMounted, onUnmounted } from 'vue';

/**
 * Reactive viewport orientation detection.
 * Returns `isPortrait` that updates when the device orientation changes.
 */
export function useViewport() {
  const isPortrait = ref(false);

  let query: MediaQueryList | null = null;

  function onChange(e: MediaQueryListEvent) {
    isPortrait.value = e.matches;
  }

  onMounted(() => {
    query = window.matchMedia('(orientation: portrait)');
    isPortrait.value = query.matches;
    query.addEventListener('change', onChange);
  });

  onUnmounted(() => {
    if (query) {
      query.removeEventListener('change', onChange);
    }
  });

  return { isPortrait };
}
