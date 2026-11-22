<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  PluginIcon · 插件图标：有 icon_url 用 <img>（/plugin-ui 同源、带 CSP），
  加载失败或没有时回落到分类色底块（pluginLook）。
-->
<script lang="ts">
  import type { Plugin } from '$api/types';
  import { Tile } from '$ui';
  import { pluginLook } from '../../app/nav';

  interface Props {
    plugin: Plugin;
    size?: 'md' | 'lg';
  }
  let { plugin, size = 'md' }: Props = $props();

  let broken = $state(false);
  const look = $derived(pluginLook(plugin));
</script>

{#if plugin.icon_url && !broken}
  <img class="icon {size}" src={plugin.icon_url} alt="" onerror={() => (broken = true)} />
{:else}
  <Tile icon={look.icon} color={look.color} {size} />
{/if}

<style>
  .icon {
    flex: none;
    width: 34px;
    height: 34px;
    border-radius: var(--r-sm);
    object-fit: cover;
  }
  .icon.lg {
    width: 44px;
    height: 44px;
    border-radius: var(--r-md);
  }
</style>
