<script setup lang="ts">
import feather from 'feather-icons';

const props = withDefaults(
  defineProps<{
    name: string;
    size?: number;
    strokeWidth?: number;
  }>(),
  {
    size: 16,
    strokeWidth: 2,
  },
);

const icon = feather.icons[props.name] ?? null;
</script>

<template>
  <span
    v-if="icon"
    class="feather-icon"
    :style="{ display: 'inline-flex', width: size + 'px', height: size + 'px' }"
    v-html="icon.toSvg({ width: size, height: size, 'stroke-width': strokeWidth })"
  />
</template>

<style>
/* Ensure all feather icons rendered via v-html inherit color */
.feather-icon svg {
  display: block;
}
</style>
