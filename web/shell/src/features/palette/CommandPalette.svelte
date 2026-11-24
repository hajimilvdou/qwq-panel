<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  CommandPalette · ⌘K 命令面板（SPEC §5）
  ───────────────────────────────────────────────────────────────
  顶部居中 640 的模态框。分组：页面 → 操作（GET /actions?q=，防抖 150，仅有权限的）
  → 最近 → 末项"问 AI：{输入}"（打开悬浮窗并带入）。
  键盘：↑↓ 移动 · Enter 选中 · Esc 关闭（参数表单里 Esc 先回到搜索）。
  ARIA：input role=combobox + listbox/option，aria-activedescendant 跟随游标。
  选中操作：有 ui_route 直接跳页；否则进入 ActionRunner 填参数、预览、执行。
-->
<script lang="ts">
  import { tick } from 'svelte';
  import { Icon, Orb, registerModalDialog, Spinner, unregisterModalDialog } from '$ui';
  import { actions as actionsApi } from '$api/endpoints';
  import type { ActionMeta } from '$api/additions';
  import { dock } from '$lib/ai/dock.svelte';
  import { palette } from '$lib/palette.svelte';
  import { useResource } from '$lib/resource.svelte';
  import { navigate } from '$lib/router.svelte';
  import { session } from '$lib/session.svelte';
  import { APP_CENTER, PRIMARY, SETTINGS, pluginNav, pluginsResource } from '../../app/nav';
  import { SETTINGS_SECTIONS } from '../settings/sections';
  import {
    OFFICIAL_PLUGIN_SEARCH_KEYWORDS,
    buildGroups,
    loadRecent,
    moveCursor,
    pushRecent,
    saveRecent,
    type PaletteItem,
  } from './items';

  let runnerMod: Promise<typeof import('./ActionRunner.svelte')> | null = null;
  const loadRunner = () => (runnerMod ??= import('./ActionRunner.svelte'));

  const plugins = useResource(pluginsResource);

  let dlg = $state<HTMLDialogElement>();
  let input = $state<HTMLInputElement>();
  let cursor = $state(0);
  let found = $state<ActionMeta[]>([]);
  let searching = $state(false);
  let searchFailed = $state(false);
  let running = $state<string | null>(null);
  let recent = $state<PaletteItem[]>(loadRecent(session.user?.user_id));
  let returnFocus: HTMLElement | null = null;

  $effect(() => {
    recent = loadRecent(session.user?.user_id);
  });

  /* ---------------------------------------------------------------- 页面目录 */
  const BUILTIN_PAGE_KEYWORDS: Readonly<Record<string, string>> = {
    '/': 'home dashboard overview 首页 概览 仪表盘',
    '/activity': 'activity operations audit log 动态 操作 日志',
    '/agent': 'agent ai chat assistant copilot 助手 对话',
    '/apps': 'apps store market plugins 应用 商店 插件',
  };
  const SETTINGS_KEYWORDS: Readonly<Record<string, string>> = {
    account: 'account profile password mfa totp 账户 资料 密码 两步验证',
    appearance: 'appearance theme dark light density accent 外观 主题 深色 浅色 密度',
    users: 'users rbac role admin operator viewer 用户 角色 权限',
    delegations: 'delegations token mcp api key 令牌 委托',
    ai: 'ai provider llm openai anthropic claude codex opencode 模型 渠道',
    system: 'system backup restore port tls entry path support 系统 备份 恢复 端口 密道 诊断',
  };

  type PageItem = Extract<PaletteItem, { kind: 'page' }>;
  const pages = $derived.by<PageItem[]>(() => {
    const nav = [...PRIMARY, APP_CENTER, ...pluginNav(plugins.data ?? [])].filter((n) => !n.perm || session.can(n.perm));
    const out: PageItem[] = nav.map((n) => {
      const kw = [
        BUILTIN_PAGE_KEYWORDS[n.href],
        n.pluginId,
        n.pluginId ? OFFICIAL_PLUGIN_SEARCH_KEYWORDS[n.pluginId] : undefined,
      ]
        .filter(Boolean)
        .join(' ');
      return { kind: 'page', id: 'page:' + n.href, label: n.label, href: n.href, icon: n.icon, keywords: kw || undefined };
    });
    if (session.can('host.plugins:install'))
      out.push({ kind: 'page', id: 'page:/apps/install', label: '安装应用', href: '/apps/install', icon: 'upload', keywords: 'install upload pkg plugin 上传 插件 安装' });
    for (const s of SETTINGS_SECTIONS)
      if (!('perm' in s) || session.can(s.perm))
        out.push({
          kind: 'page',
          id: 'page:/settings/' + s.id,
          label: `设置 · ${s.title}`,
          href: `/settings/${s.id}`,
          icon: SETTINGS.icon,
          keywords: `settings ${s.id} ${SETTINGS_KEYWORDS[s.id] ?? ''}`.trim(),
        });
    return out;
  });

  const canAsk = $derived(session.can('host.agent_sessions:write'));
  const authorizedRecent = $derived.by(() => {
    const allowedPages = new Set(pages.map((p) => p.id));
    return recent.filter((item) => {
      if (item.kind === 'page') return allowedPages.has(item.id);
      if (item.kind === 'action') return !item.action.permission || session.can(item.action.permission);
      return false;
    });
  });
  const groups = $derived(buildGroups({ q: palette.query, pages, actions: found, recent: authorizedRecent, canAsk }));
  const flat = $derived(groups.flatMap((g) => g.items));
  const active = $derived(flat[Math.min(cursor, flat.length - 1)]);

  /* ---------------------------------------------------------------- 操作搜索（防抖 150） */
  $effect(() => {
    const q = palette.query.trim();
    cursor = 0;
    if (!q || !palette.opened) {
      found = [];
      searching = false;
      return;
    }
    const ctrl = new AbortController();
    const t = setTimeout(() => {
      searching = true;
      actionsApi
        .search(q, { signal: ctrl.signal, limit: 8 })
        .then((r) => {
          found = r.items;
          searchFailed = false;
        })
        .catch((e: unknown) => {
          if ((e as { name?: string }).name !== 'AbortError') searchFailed = true;
        })
        .finally(() => {
          if (!ctrl.signal.aborted) searching = false;
        });
    }, 150);
    return () => {
      clearTimeout(t);
      ctrl.abort();
    };
  });

  /* ---------------------------------------------------------------- 开关 */
  $effect(() => {
    const el = dlg;
    if (!el) return;
    if (palette.opened && !el.open) {
      returnFocus = document.activeElement as HTMLElement | null;
      running = null;
      cursor = 0;
      el.showModal();
      registerModalDialog(el);
      void tick().then(() => input?.select());
    } else if (!palette.opened && el.open) {
      unregisterModalDialog(el);
      el.close();
    }
  });

  $effect(() => {
    const el = dlg;
    return () => {
      if (el) unregisterModalDialog(el);
    };
  });

  function onclose() {
    unregisterModalDialog(dlg);
    palette.close();
    running = null;
    if (!dock.expanded) {
      returnFocus?.focus?.();
    }
    returnFocus = null;
  }

  function oncancel(e: Event) {
    /* 表单里 Esc 先回到搜索 */
    if (running) {
      e.preventDefault();
      back();
    }
  }

  async function back() {
    running = null;
    await tick();
    input?.focus();
  }

  /* ---------------------------------------------------------------- 选中 */
  function choose(item: PaletteItem | undefined) {
    if (!item) return;
    if (item.kind === 'ask') {
      palette.close();
      dock.open({ prompt: item.prompt });
      return;
    }
    recent = pushRecent(recent, item);
    saveRecent(recent, session.user?.user_id);
    if (item.kind === 'page') {
      palette.close();
      navigate(item.href);
    } else if (item.action.ui_route?.startsWith('/') && !item.action.ui_route.startsWith('//')) {
      palette.close();
      navigate(item.action.ui_route);
    } else {
      running = item.action.id;
    }
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.isComposing) return;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      cursor = moveCursor(cursor, e.key === 'ArrowDown' ? 1 : -1, flat.length);
      void tick().then(() => document.getElementById(optId(active) ?? '')?.scrollIntoView({ block: 'nearest' }));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      choose(active);
    }
  }

  const optId = (it: PaletteItem | undefined) => (it ? 'pal-' + it.id.replace(/[^\w-]/g, '_') : undefined);
  const iconOf = (it: PaletteItem) => (it.kind === 'page' ? it.icon : 'play');
</script>

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
<dialog
  bind:this={dlg}
  class="pal"
  aria-label="搜索页面和操作"
  {onclose}
  {oncancel}
  onclick={(e) => e.target === dlg && palette.close()}
>
  {#if palette.opened}
    {#if running}
      {#await loadRunner()}
        <div class="search"><Spinner size={16} label="加载操作表单" /></div>
      {:then mod}
        <mod.default actionId={running} onback={back} ondone={() => palette.close()} />
      {/await}
    {:else}
      <div class="search">
        <Icon name="search" size={20} />
        <input
          bind:this={input}
          bind:value={palette.query}
          type="text"
          role="combobox"
          aria-expanded="true"
          aria-controls="pal-list"
          aria-autocomplete="list"
          aria-activedescendant={optId(active)}
          placeholder={canAsk ? '搜索页面和操作，或直接问 AI…' : '搜索页面和操作…'}
          autocomplete="off"
          spellcheck="false"
          {onkeydown}
        />
        {#if searching}<Spinner size={16} label="搜索中" />{/if}
        <kbd>Esc</kbd>
      </div>

      <div id="pal-list" class="list" role="listbox" aria-label="结果">
        {#each groups as g (g.title)}
          <div role="group" aria-labelledby="pal-g-{g.title}">
            <p class="gt" id="pal-g-{g.title}">{g.title}</p>
            {#each g.items as it (it.id)}
              <div
                id={optId(it)}
                role="option"
                tabindex="-1"
                class="opt"
                class:ask={it.kind === 'ask'}
                aria-selected={it === active}
                onclick={() => choose(it)}
                onmousemove={() => (cursor = flat.indexOf(it))}
              >
                {#if it.kind === 'ask'}
                  <Orb size={20} />
                {:else}
                  <span class="ic"><Icon name={iconOf(it)} size={16} /></span>
                {/if}
                <span class="lbl">{it.label}</span>
                {#if it.kind === 'action'}
                  <span class="meta">{it.action.source === 'plugin' ? '来自插件' : '系统'}</span>
                {/if}
                {#if it === active}<span class="enter" aria-hidden="true">↵</span>{/if}
              </div>
            {/each}
          </div>
        {/each}
        {#if searchFailed && palette.query.trim()}
          <p class="note">操作搜索暂时不可用，页面跳转不受影响。</p>
        {/if}
      </div>
    {/if}
  {/if}
</dialog>

<style>
  .pal {
    width: min(640px, calc(100vw - 32px));
    max-height: none;
    margin: 12vh auto auto;
    padding: 0;
    border: 1px solid var(--line);
    border-radius: var(--r-xl);
    background: var(--surface);
    color: var(--text);
    box-shadow: var(--shadow-3);
    overflow: hidden;
  }
  .pal[open] {
    animation: qwq-rise-in var(--dur-2) var(--ease-out);
  }
  .pal::backdrop {
    background: var(--scrim);
  }
  .search {
    display: flex;
    align-items: center;
    gap: var(--s-3);
    padding: 0 var(--s-5);
    height: 60px;
    border-bottom: 1px solid var(--line);
    color: var(--text-3);
  }
  input {
    flex: 1;
    min-width: 0;
    height: 100%;
    border: 0;
    outline: 0;
    background: none;
    color: var(--text);
    font: inherit;
    font-size: var(--fs-lg);
  }
  input::placeholder {
    color: var(--text-3);
  }
  kbd {
    padding: 2px 6px;
    border: 1px solid var(--line);
    border-radius: var(--r-xs);
    font-family: inherit;
    font-size: var(--fs-2xs);
    color: var(--text-3);
  }
  .list {
    max-height: min(56vh, 480px);
    overflow-y: auto;
    padding: var(--s-2);
  }
  .gt {
    margin: var(--s-2) var(--s-3) var(--s-1);
    font-size: var(--fs-xs);
    font-weight: var(--fw-medium);
    color: var(--text-3);
  }
  .opt {
    display: flex;
    align-items: center;
    gap: var(--s-3);
    min-height: 44px;
    padding: 0 var(--s-3);
    border-radius: var(--r-md);
    cursor: pointer;
  }
  .opt[aria-selected='true'] {
    background: var(--accent-soft);
  }
  .opt.ask[aria-selected='true'] {
    background: var(--ai-soft);
  }
  .ic {
    display: grid;
    place-items: center;
    width: 28px;
    height: 28px;
    border-radius: var(--r-sm);
    background: var(--surface-3);
    color: var(--text-2);
  }
  .lbl {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .ask .lbl {
    color: var(--ai-text);
    font-weight: var(--fw-medium);
  }
  .meta {
    font-size: var(--fs-xs);
    color: var(--text-3);
  }
  .enter {
    color: var(--text-3);
    font-size: var(--fs-sm);
  }
  .note {
    margin: var(--s-2) var(--s-3);
    font-size: var(--fs-xs);
    color: var(--text-3);
  }
  @media (max-width: 860px) {
    .pal {
      margin-top: var(--s-4);
    }
  }
</style>
