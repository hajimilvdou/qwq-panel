<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  设置 · 外观（SPEC §7）：主题、主题色、动效、密度——只存 localStorage（prefs）
  色板每格自带 data-accent，局部取该主题色的 --accent 渲染，不硬编码色值。
-->
<script lang="ts">
  import { Card, Icon, Segmented } from '$ui';
  import { ACCENTS, prefs, type Accent, type Density, type LayoutPref, type MotionPref, type ThemePref } from '$lib/prefs.svelte';

  const THEME_OPTS = [
    { value: 'light', label: '浅色' },
    { value: 'dark', label: '深色' },
    { value: 'system', label: '跟随系统' },
  ] as const satisfies readonly { value: ThemePref; label: string }[];
  const MOTION_OPTS = [
    { value: 'full', label: '完整' },
    { value: 'reduced', label: '减弱' },
    { value: 'off', label: '关闭' },
    { value: 'system', label: '跟随系统' },
  ] as const satisfies readonly { value: MotionPref; label: string }[];
  const DENSITY_OPTS = [
    { value: 'comfortable', label: '舒适' },
    { value: 'compact', label: '紧凑' },
  ] as const satisfies readonly { value: Density; label: string }[];
  const LAYOUT_OPTS = [
    { value: 'top', label: '顶部横向栏（默认）' },
    { value: 'side', label: '左侧折叠栏' },
  ] as const satisfies readonly { value: LayoutPref; label: string }[];
  const ACCENT_NAMES: Record<Accent, string> = { rose: '莓果可可', sky: '晴空', violet: '紫罗兰', teal: '青碧', coral: '珊瑚', green: '草木' };
</script>

<Card title="主题" icon="sun" color="amber">
  <Segmented label="主题" options={THEME_OPTS} value={prefs.theme} onchange={(v) => prefs.set('theme', v)} />
</Card>

<Card title="主题色" icon="eye" color="violet" subtitle="按钮、选中项和焦点环会用这个颜色">
  <div class="swatches" role="radiogroup" aria-label="主题色">
    {#each ACCENTS as a (a)}
      <button
        type="button"
        role="radio"
        aria-checked={prefs.accent === a}
        class="swatch"
        data-accent={a}
        onclick={() => prefs.set('accent', a)}
      >
        <span class="dot">{#if prefs.accent === a}<Icon name="check" size={16} />{/if}</span>
        <span class="name">{ACCENT_NAMES[a]}</span>
      </button>
    {/each}
  </div>
</Card>

<Card title="动效" icon="play" color="pink" subtitle="减弱：去掉弹性与循环动画；关闭：所有过渡立即完成">
  <Segmented label="动效" options={MOTION_OPTS} value={prefs.motion} onchange={(v) => prefs.set('motion', v)} />
</Card>

<Card title="导航布局" icon="sidebar" color="teal" subtitle="默认采用简洁顶部横向栏；切为左侧折叠栏时自动隐藏顶栏并支持收起展开">
  <Segmented label="导航布局" options={LAYOUT_OPTS} value={prefs.layout} onchange={(v) => prefs.set('layout', v)} />
</Card>

<Card title="密度" icon="menu" color="slate" subtitle="紧凑模式下表格行与控件更矮">
  <Segmented label="密度" options={DENSITY_OPTS} value={prefs.density} onchange={(v) => prefs.set('density', v)} />
</Card>

<style>
  .swatches {
    display: flex;
    flex-wrap: wrap;
    gap: var(--s-3);
  }
  .swatch {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    min-width: 64px;
    padding: var(--s-2);
    border: 0;
    border-radius: var(--r-md);
    background: transparent;
    color: var(--text-2);
    font: inherit;
    font-size: var(--fs-xs);
    cursor: pointer;
  }
  .swatch:hover {
    background: var(--surface-3);
  }
  .dot {
    display: grid;
    place-items: center;
    width: 40px;
    height: 40px;
    border-radius: 50%;
    background: var(--accent-strong);
    color: var(--on-accent);
    box-shadow: 0 0 0 3px var(--surface), 0 0 0 5px transparent;
    transition: box-shadow var(--dur-2) var(--ease);
  }
  .swatch[aria-checked='true'] .dot {
    box-shadow: 0 0 0 3px var(--surface), 0 0 0 5px var(--accent);
  }
  .swatch[aria-checked='true'] .name {
    color: var(--text);
    font-weight: var(--fw-semibold);
  }
</style>
