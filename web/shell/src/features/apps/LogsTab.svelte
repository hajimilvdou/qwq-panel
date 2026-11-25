<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  LogsTab · 插件日志（带模块级缓存，换页回来零空白骨架闪烁）
-->
<script module lang="ts">
  import type { PluginLogLine as CachedLogLine } from '$api/additions';
  const logsCache = new Map<string, { items: CachedLogLine[]; nextCursor?: string; truncated: boolean }>();
</script>

<script lang="ts">
  import { untrack } from 'svelte';
  import { Button, Card, EmptyState, ErrorState, IconButton, Segmented, Skeleton } from '$ui';
  import { plugins } from '$api/endpoints';
  import type { PluginLogLine } from '$api/additions';
  import { describeError } from '$lib/errors';
  import { dateTime } from '$lib/format';

  interface Props {
    pluginId: string;
  }
  let { pluginId }: Props = $props();
  const pid = untrack(() => pluginId);

  type Stream = 'all' | 'stdout' | 'stderr';
  const STREAMS = [
    { value: 'all', label: '全部' },
    { value: 'stdout', label: '输出' },
    { value: 'stderr', label: '错误' },
  ] as const satisfies readonly { value: Stream; label: string }[];

  let stream = $state<Stream>('all');
  const cacheKey = (s: Stream) => `${pid}:${s}`;
  const initialHit = untrack(() => logsCache.get(cacheKey('all')));
  let lines = $state<PluginLogLine[]>(initialHit?.items ?? []);
  let cursor = $state<string | undefined>(initialHit?.nextCursor);
  let truncated = $state(initialHit?.truncated ?? false);
  let status = $state<'loading' | 'ready' | 'error'>(initialHit ? 'ready' : 'loading');
  let refreshing = $state(false);
  let error = $state<unknown>(null);
  let more = $state(false);
  let ctrl: AbortController | null = null;

  async function fetchPage(after?: string) {
    const q = { limit: 100, cursor: after, stream: stream === 'all' ? undefined : stream };
    return plugins.logs(pid, q);
  }

  async function reload() {
    ctrl?.abort();
    ctrl = new AbortController();
    const mine = ctrl;
    const key = cacheKey(stream);
    const hit = logsCache.get(key);
    if (hit) {
      lines = hit.items;
      cursor = hit.nextCursor;
      truncated = hit.truncated;
      status = 'ready';
      refreshing = true;
    } else if (!lines.length) {
      status = 'loading';
    }
    try {
      const page = await fetchPage();
      if (mine.signal.aborted) return;
      lines = page.items;
      cursor = page.next_cursor;
      truncated = page.truncated;
      logsCache.set(key, { items: page.items, nextCursor: page.next_cursor, truncated: page.truncated });
      status = 'ready';
    } catch (err) {
      if (mine.signal.aborted) return;
      error = err;
      if (!lines.length) status = 'error';
    } finally {
      if (ctrl === mine) refreshing = false;
    }
  }

  async function follow() {
    if (!cursor || more) return;
    more = true;
    try {
      const page = await fetchPage(cursor);
      lines = [...lines, ...page.items];
      cursor = page.next_cursor;
      logsCache.set(cacheKey(stream), { items: lines, nextCursor: cursor, truncated });
    } catch (err) {
      error = err;
    } finally {
      more = false;
    }
  }

  $effect(() => {
    void stream;
    untrack(() => {
      void reload();
    });
    return () => ctrl?.abort();
  });
</script>

<Card title="运行日志" subtitle={refreshing ? '正在同步最新日志…' : undefined} icon="menu" color="slate">
  {#snippet actions()}
    <Segmented label="日志流" size="sm" options={STREAMS} bind:value={stream} />
    <IconButton icon="refresh" label="刷新日志" size="sm" onclick={reload} />
  {/snippet}

  {#if status === 'loading'}
    <Skeleton lines={6} height={14} />
  {:else if status === 'error' && !lines.length}
    <ErrorState compact message={describeError(error).message} requestId={describeError(error).requestId} onretry={reload} />
  {:else if !lines.length}
    <EmptyState compact title="还没有日志" />
  {:else}
    {#if cursor}
      <div class="older"><Button variant="plain" size="sm" loading={more} onclick={follow}>加载后续日志</Button></div>
    {/if}
    <ol class="log mono" aria-label="日志内容">
      {#each lines as l, i (i)}
        <li class:err={l.stream === 'stderr'}>
          <time datetime={l.at}>{dateTime(l.at).slice(11)}</time>
          <span class="txt">{l.line}</span>
        </li>
      {/each}
    </ol>
    {#if truncated}<p class="tiny faint">还有更多日志，点上方按钮继续跟随。</p>{/if}
  {/if}
</Card>

<style>
  .older {
    display: flex;
    justify-content: center;
    margin-bottom: var(--s-2);
  }
  .log {
    max-height: 520px;
    margin: 0;
    padding: var(--s-3) 0;
    overflow: auto;
    border-radius: var(--r-md);
    background: var(--surface-2);
    list-style: none;
    font-size: var(--fs-xs);
    line-height: 1.7;
  }
  li {
    display: flex;
    gap: var(--s-3);
    padding: 0 var(--s-4);
  }
  li:hover {
    background: var(--surface-3);
  }
  time {
    flex: none;
    color: var(--text-3);
  }
  .txt {
    min-width: 0;
    white-space: pre-wrap;
    word-break: break-all;
  }
  li.err .txt {
    color: var(--bad-text);
  }
  p {
    margin: var(--s-2) 0 0;
  }
</style>
