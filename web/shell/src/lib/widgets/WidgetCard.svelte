<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  WidgetCard · 单个声明式小组件（stat / series / checks / list）
  ──────────────────────────────────────────────────────────────────────────
  <WidgetCard slot={slot} onlevel={(l) => …} />

  数据：POST …/operations/{op}（effect=read，空 payload，无幂等键）
  轮询：refresh_seconds（下限 2 秒）；页面隐藏或宿主断线时暂停，恢复时立即补取；
        单飞——上一次没回来不发下一次；卸载即中止。
  失败：只在本卡显示错误与重试，健康度上报 undefined（不把未知当故障）。
-->
<script lang="ts">
  import { untrack } from 'svelte';
  import { plugins as pluginsApi } from '$api/endpoints';
  import type { Level } from '$api/additions';
  import { describeError } from '$lib/errors';
  import { events } from '$lib/events.svelte';
  import { relativeTime } from '$lib/format';
  import { Card, EmptyState, ErrorState, Icon, Ring, Segmented, Skeleton, Sparkline, CATEGORY_COLORS, type CategoryColor } from '$ui';
  import { ICONS, type IconName } from '$ui/icons';
  import { levelOf, parseWidget, refreshMs, WidgetShapeError, type WidgetData, type WidgetSlot } from './index';

  let chartMod: Promise<typeof import('$ui/SeriesChart.svelte')> | null = null;
  const loadSeriesChart = () => (chartMod ??= import('$ui/SeriesChart.svelte'));

  interface Props {
    slot: WidgetSlot;
    onlevel?: (level: Level | undefined) => void;
  }
  let { slot, onlevel }: Props = $props();

  const w = $derived(slot.widget);
  const KIND_ICON: Record<WidgetSlot['widget']['kind'], IconName> = { stat: 'activity', series: 'activity', checks: 'shield', list: 'clock' };
  const icon = $derived<IconName>(w.icon && w.icon in ICONS ? (w.icon as IconName) : KIND_ICON[w.kind]);
  const color = $derived<CategoryColor | undefined>(
    w.color && (CATEGORY_COLORS as readonly string[]).includes(w.color) ? (w.color as CategoryColor) : undefined,
  );

  /* ---------------------------------------------------------------- 状态 */
  let data = $state<WidgetData | null>(null);
  let failure = $state<{ message: string; fromPlugin?: string; requestId?: string } | null>(null);
  let retryNow = $state(0);
  let detailDlg = $state<HTMLDialogElement>();
  let detailOpen = $state(false);

  $effect(() => {
    if (!detailDlg) return;
    if (detailOpen && !detailDlg.open) detailDlg.showModal();
    else if (!detailOpen && detailDlg.open) detailDlg.close();
  });

  function toFailure(err: unknown) {
    if (err instanceof WidgetShapeError) return { message: err.message };
    const v = describeError(err);
    return { message: v.message, fromPlugin: v.fromPlugin, requestId: v.requestId };
  }

  /* ---------------------------------------------------------------- 轮询 */
  $effect(() => {
    void retryNow;
    const { plugin, widget } = slot;
    const every = refreshMs(widget);
    let timer: ReturnType<typeof setTimeout> | null = null;
    let ctrl: AbortController | null = null;
    let disposed = false;

    const paused = () => document.hidden || events.offline;
    const later = () => {
      if (!disposed) timer = setTimeout(tick, every);
    };

    async function tick() {
      timer = null;
      if (paused()) return; /* 恢复时由 visibilitychange / offline 监听补取 */
      ctrl = new AbortController();
      try {
        const r = await pluginsApi.invoke(
          { pluginId: plugin.plugin_id, operation: widget.operation, placement: plugin.placement },
          {},
          { signal: ctrl.signal },
        );
        if (r.status !== 'SUCCEEDED') {
          failure = { message: r.error?.title ?? '应用没有给出数据', fromPlugin: r.error?.detail, requestId: r.error?.request_id };
          onlevel?.(undefined);
        } else {
          data = parseWidget(widget.kind, r.result);
          failure = null;
          onlevel?.(levelOf(data));
        }
      } catch (err) {
        if (ctrl.signal.aborted) return;
        failure = toFailure(err);
        onlevel?.(undefined);
      }
      ctrl = null;
      later();
    }

    const resume = () => {
      if (!paused() && !timer && !ctrl) void tick();
    };
    document.addEventListener('visibilitychange', resume);
    untrack(() => void tick()); /* 断线由下方边沿监听负责，这里不追踪 events.offline */

    return () => {
      disposed = true;
      if (timer) clearTimeout(timer);
      ctrl?.abort();
      document.removeEventListener('visibilitychange', resume);
      onlevel?.(undefined);
    };
  });

  /* 宿主断线 → 恢复：立即补取（只看边沿，避免与失败状态互相触发） */
  let wasOffline = false;
  $effect(() => {
    const off = events.offline;
    if (wasOffline && !off) retryNow++;
    wasOffline = off;
  });

  /* ---------------------------------------------------------------- series 时间窗 */
  type Win = 'all' | '15m' | '5m';
  let win = $state<Win>('all');
  const WIN_SEC: Record<Win, number> = { all: Infinity, '15m': 900, '5m': 300 };
  const seriesView = $derived.by(() => {
    if (data?.kind !== 'series') return null;
    const s = data.data.series;
    const t1 = Math.max(...s.map((x) => x.points[x.points.length - 1]?.[0] ?? -Infinity));
    const span = t1 - Math.min(...s.map((x) => x.points[0]?.[0] ?? Infinity));
    const options = (['5m', '15m'] as const)
      .filter((k) => span > WIN_SEC[k])
      .map((k) => ({ value: k as Win, label: k === '5m' ? '5 分钟' : '15 分钟' }));
    const cut = t1 - WIN_SEC[win];
    return {
      options: options.length ? [...options, { value: 'all' as Win, label: '全部' }] : [],
      series: s.map((x) => ({ ...x, points: x.points.filter(([t]) => t >= cut) })),
    };
  });

  const ringTone = (l: Level | undefined) => (l === 'warn' || l === 'bad' ? l : 'accent');
  const LEVEL_TEXT: Record<Level, string> = { ok: '正常', warn: '需留意', bad: '有问题' };
</script>

<Card title={w.title} {icon} color={color ?? 'slate'} as="article">
  {#snippet actions()}
    {#if seriesView?.options.length}
      <Segmented size="sm" label="时间范围" options={seriesView.options} bind:value={win} />
    {/if}
  {/snippet}

  {#if failure && !data}
    <ErrorState compact message={failure.message} fromPlugin={failure.fromPlugin} requestId={failure.requestId} onretry={() => retryNow++} />
  {:else if !data && events.offline}
    <EmptyState compact mood="warn" title="暂时连不上服务器" description="连接恢复后自动刷新" />
  {:else if !data}
    <Skeleton lines={w.kind === 'stat' ? 2 : 4} label="{w.title}加载中" />
  {:else}
    {#if failure}
      <p class="stale" role="status"><Icon name="alert" size={14} />{failure.message}，显示的是上次的数据</p>
    {/if}

    {#if data.kind === 'stat'}
      {@const d = data.data}
      {#if d.percent !== undefined}
        <button type="button" class="stat stat-btn" onclick={() => (detailOpen = true)} aria-haspopup="dialog">
          <div>
            <p class="value num">{d.value}{#if d.unit}<small>{d.unit}</small>{/if}</p>
            {#if d.sub}<p class="sub">{d.sub}</p>{/if}
            {#if d.level && d.level !== 'ok'}<p class="sub lv-{d.level}">{LEVEL_TEXT[d.level]}</p>{/if}
          </div>
          <Ring value={d.percent} label="{w.title} {d.percent}%" tone={ringTone(d.level)} />
        </button>
        <dialog
          bind:this={detailDlg}
          class="m-dlg"
          aria-label="{w.title} 占用详情"
          onclose={() => (detailOpen = false)}
          onclick={(e) => {
            if (e.target === detailDlg) detailOpen = false;
          }}
        >
          {#if detailOpen}
            <div class="m-box">
              <header class="m-head">
                <h3>{w.title} · 实时占用详情</h3>
                <button type="button" class="m-x" aria-label="关闭" onclick={() => (detailOpen = false)}>
                  <Icon name="x" size={16} />
                </button>
              </header>
              <div class="m-hero">
                <Ring value={d.percent} label="{w.title} {d.percent}%" tone={ringTone(d.level)} size={96} />
                <div>
                  <p class="value num">{d.value}{#if d.unit}<small>{d.unit}</small>{/if}</p>
                  {#if d.sub}<p class="sub">{d.sub}</p>{/if}
                  <p class="sub">当前状态：{LEVEL_TEXT[d.level ?? 'ok']} · 来源插件 {slot.plugin.plugin_id}</p>
                </div>
              </div>
              <footer class="m-foot">
                <a class="m-link" href="/plugins/{encodeURIComponent(slot.plugin.plugin_id)}" onclick={() => (detailOpen = false)}>查看插件详情</a>
                <button type="button" class="m-ok" onclick={() => (detailOpen = false)}>关闭</button>
              </footer>
            </div>
          {/if}
        </dialog>
      {:else}
        <div class="stat">
          <div>
            <p class="value num">{d.value}{#if d.unit}<small>{d.unit}</small>{/if}</p>
            {#if d.sub}<p class="sub">{d.sub}</p>{/if}
            {#if d.level && d.level !== 'ok'}<p class="sub lv-{d.level}">{LEVEL_TEXT[d.level]}</p>{/if}
          </div>
          {#if d.spark && d.spark.length > 1}
            <Sparkline points={d.spark} tone={color ?? 'accent'} />
          {/if}
        </div>
      {/if}
    {:else if data.kind === 'series' && seriesView}
      {#await loadSeriesChart()}
        <Skeleton lines={4} label="{w.title}图表加载中" />
      {:then mod}
        <mod.default label="{w.title}趋势" unit={data.data.unit} max={data.data.max} series={seriesView.series} height={160} />
      {/await}
    {:else if data.kind === 'checks'}
      {@const d = data.data}
      {@const top = Math.max(1, ...(d.bars ?? []))}
      {#if d.headline}
        <p class="headline"><b class="num">{d.headline.value}</b><span>{d.headline.label}</span></p>
      {/if}
      {#if d.bars?.length}
        <div class="bars" aria-hidden="true">
          {#each d.bars as b, i (i)}<span style:height="{Math.max(4, (b / top) * 100)}%"></span>{/each}
        </div>
      {/if}
      <ul class="checks">
        {#each d.items as it, i (i)}
          <li class="lv-{it.level}">
            <Icon name={it.level === 'ok' ? 'check' : 'alert'} size={16} />
            <span class="sr-only">{LEVEL_TEXT[it.level]}：</span>{it.label}<b>{it.value}</b>
          </li>
        {/each}
      </ul>
    {:else if data.kind === 'list'}
      {#if data.data.items.length}
        <ul class="list">
          {#each data.data.items as it, i (i)}
            <li>
              <i class="dot lv-{it.level ?? 'none'}" aria-hidden="true"></i>
              <div>
                <b>{it.title}</b>
                {#if it.sub}<small>{it.sub}</small>{/if}
              </div>
              {#if it.at}<time datetime={it.at}>{relativeTime(it.at)}</time>{/if}
            </li>
          {/each}
        </ul>
      {:else}
        <p class="sub">暂时没有记录</p>
      {/if}
    {/if}
  {/if}
</Card>

<style>
  .stale {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-bottom: var(--s-2);
    color: var(--warn-text);
    font-size: var(--fs-xs);
  }

  /* ---------------------------------------------------------------- stat */
  .stat {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: var(--s-3);
  }
  .stat-btn {
    width: 100%;
    text-align: left;
    border-radius: var(--r-md);
    padding: 4px;
    margin: -4px;
    transition: background var(--dur-1) var(--ease);
  }
  .stat-btn:hover {
    background: var(--surface-2);
  }
  .m-dlg {
    padding: 0;
    border: 0;
    border-radius: var(--r-xl);
    background: transparent;
    max-width: min(440px, calc(100vw - 32px));
    width: 100%;
  }
  .m-dlg::backdrop {
    background: var(--scrim);
    backdrop-filter: blur(2px);
  }
  .m-box {
    display: grid;
    gap: var(--s-4);
    padding: var(--s-5);
    border-radius: var(--r-xl);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-3);
  }
  .m-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .m-head h3 {
    font-size: var(--fs-lg);
  }
  .m-x {
    display: inline-grid;
    place-items: center;
    width: 30px;
    height: 30px;
    border-radius: var(--r-pill);
    color: var(--text-3);
  }
  .m-x:hover {
    background: var(--surface-2);
    color: var(--text);
  }
  .m-hero {
    display: flex;
    align-items: center;
    gap: var(--s-4);
  }
  .m-foot {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-top: var(--s-3);
    border-top: 1px solid var(--line);
  }
  .m-link {
    color: var(--accent-text);
    font-size: var(--fs-sm);
    font-weight: var(--fw-medium);
  }
  .m-ok {
    height: 32px;
    padding: 0 14px;
    border-radius: var(--r-pill);
    background: var(--accent-strong);
    color: var(--on-accent);
    font-size: var(--fs-sm);
    font-weight: var(--fw-semibold);
  }
  .value {
    font-size: var(--fs-4xl);
    font-weight: var(--fw-semibold);
    line-height: 1;
  }
  .value small {
    margin-left: 3px;
    color: var(--text-3);
    font-size: var(--fs-md);
    font-weight: var(--fw-semibold);
  }
  .sub {
    margin-top: var(--s-2);
    color: var(--text-3);
    font-size: var(--fs-xs);
  }

  /* ---------------------------------------------------------------- checks */
  .headline {
    display: flex;
    align-items: baseline;
    flex-wrap: wrap;
    gap: 8px;
  }
  .headline b {
    font-size: var(--fs-4xl);
    font-weight: var(--fw-bold);
    line-height: 1.1;
  }
  .headline span {
    color: var(--text-3);
    font-size: var(--fs-xs);
  }
  .bars {
    display: flex;
    align-items: flex-end;
    gap: 3px;
    height: 46px;
    margin: var(--s-3) 0 var(--s-4);
  }
  .bars span {
    flex: 1;
    border-radius: 3px;
    background: color-mix(in oklab, var(--accent) 55%, var(--surface));
  }
  .checks {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .checks li {
    display: flex;
    align-items: center;
    gap: 10px;
    color: var(--text-2);
  }
  .checks li b {
    margin-left: auto;
    color: var(--text);
    font-weight: var(--fw-semibold);
    text-align: end;
  }
  .checks .lv-ok :global(svg) { color: var(--ok); }
  .checks .lv-warn :global(svg) { color: var(--warn); }
  .checks .lv-bad :global(svg) { color: var(--bad); }

  /* ---------------------------------------------------------------- list */
  .list {
    display: flex;
    flex-direction: column;
  }
  .list li {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 0;
    border-top: 1px solid var(--line);
  }
  .list li:first-child {
    border-top: 0;
    padding-top: 0;
  }
  .list div {
    display: flex;
    flex-direction: column;
    min-width: 0;
    line-height: 1.4;
  }
  .list b {
    font-weight: var(--fw-semibold);
  }
  .list small {
    color: var(--text-3);
    font-size: var(--fs-xs);
  }
  .list time {
    margin-left: auto;
    padding-left: var(--s-2);
    color: var(--text-3);
    font-size: var(--fs-xs);
    white-space: nowrap;
  }
  .dot {
    flex: none;
    width: 8px;
    height: 8px;
    margin-top: 7px;
    border-radius: 50%;
    background: var(--line-strong);
  }
  .dot.lv-ok { background: var(--ok); }
  .dot.lv-warn { background: var(--warn); }
  .dot.lv-bad { background: var(--bad); }

  .sub.lv-warn { color: var(--warn-text); }
  .sub.lv-bad { color: var(--bad-text); }
</style>
