<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Avatar · 行为人头像
  ───────────────────────────────────────────────────────────────
  kind   human（字母头像，颜色按名字稳定取）| ai（极光小球）| system（齿轮）
  size   sm 30 | md 36
  <Avatar name="Alice" />   <Avatar kind="ai" name="AI 助手" />
-->
<script lang="ts">
  import Icon from './Icon.svelte';
  import Orb from './Orb.svelte';

  interface Props {
    name?: string;
    kind?: 'human' | 'ai' | 'system';
    size?: 'sm' | 'md';
    /** 显示文字说明（默认装饰性，由旁边文本说明是谁） */
    label?: boolean;
  }
  let { name = '', kind = 'human', size = 'md', label = false }: Props = $props();

  const PALETTES = ['p0', 'p1', 'p2', 'p3', 'p4', 'p5'];
  const letter = $derived((Array.from(name.trim())[0] ?? '?').toUpperCase());
  const palette = $derived.by(() => {
    let h = 0;
    for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
    return PALETTES[h % PALETTES.length];
  });
  const px = $derived(size === 'sm' ? 30 : 36);
</script>

{#if kind === 'ai'}
  <Orb size={px} label={label ? name || 'AI' : undefined} />
{:else}
  <span
    class="av {size} {kind === 'system' ? 'sys' : palette}"
    role={label ? 'img' : undefined}
    aria-label={label ? name : undefined}
    aria-hidden={label ? undefined : 'true'}
  >
    {#if kind === 'system'}<Icon name="gear" size={size === 'sm' ? 16 : 18} />{:else}{letter}{/if}
  </span>
{/if}

<style>
  .av {
    display: inline-grid;
    place-items: center;
    flex: none;
    width: 36px;
    height: 36px;
    border-radius: 50%;
    color: #fff;
    font-weight: var(--fw-bold);
    line-height: 1;
    user-select: none;
  }
  .sm {
    width: 30px;
    height: 30px;
    font-size: var(--fs-sm);
  }
  /* 渐变两端都足够深，白字 ≥ 3:1（大号粗体字形） */
  .p0 { background: linear-gradient(135deg, #f08a3c, #e0466b); }
  .p1 { background: linear-gradient(135deg, #2fb59a, #2f7fd9); }
  .p2 { background: linear-gradient(135deg, #8a63f0, #5b48d9); }
  .p3 { background: linear-gradient(135deg, #e0559a, #b8339a); }
  .p4 { background: linear-gradient(135deg, #3b9be8, #3456d1); }
  .p5 { background: linear-gradient(135deg, #2aa86b, #12806a); }
  .sys {
    background: var(--surface-3);
    color: var(--text-2);
  }
</style>
