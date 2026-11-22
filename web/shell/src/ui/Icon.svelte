<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Icon · 描边图标
  ───────────────────────────────────────────────────────────────
  <Icon name="home" />                装饰性（aria-hidden）
  <Icon name="alert" label="警告" />  有含义时给 label（role="img"）
  size 默认 20；颜色随 currentColor。
-->
<script lang="ts">
  import { ICONS, type IconName } from './icons';

  interface Props {
    name: IconName;
    size?: number;
    label?: string;
    class?: string;
  }
  let { name, size = 20, label, class: cls = '' }: Props = $props();

  const shapes = $derived(ICONS[name]);
</script>

<svg
  class="icon {cls}"
  width={size}
  height={size}
  viewBox="0 0 24 24"
  role={label ? 'img' : undefined}
  aria-label={label}
  aria-hidden={label ? undefined : 'true'}
>
  {#each shapes as s, i (i)}
    {#if 'd' in s}
      <path d={s.d} />
    {:else if 'c' in s}
      <circle cx={s.c[0]} cy={s.c[1]} r={s.c[2]} />
    {:else}
      <rect x={s.r[0]} y={s.r[1]} width={s.r[2]} height={s.r[3]} rx={s.r[4]} />
    {/if}
  {/each}
</svg>
