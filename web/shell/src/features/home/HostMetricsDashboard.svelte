<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  HostMetricsDashboard · 主页 C 位内置宿主资源监控
  ──────────────────────────────────────────────────────────────────────────────
  直接归属底层框架（GET /api/v1/system/metrics），无需安装任何插件即可在主页实时查看
  CPU、负载、内存、Swap、磁盘与网络实时速率；模块级快照缓存保证换页回主页 0ms 瞬显。
-->
<script module lang="ts">
  import type { SystemHostMetrics } from '$api/additions';
  let cachedMetrics: SystemHostMetrics | null = null;
  let cachedAt = 0;
</script>

<script lang="ts">
  import { untrack } from 'svelte';
  import type { Level } from '$api/additions';
  import { system } from '$api/endpoints-core';
  import { events } from '$lib/events.svelte';
  import { bytes as fmtBytes } from '$lib/format';
  import { Icon, Sparkline, Tile } from '$ui';

  interface Props {
    onlevel?: (level: Level) => void;
  }
  let { onlevel }: Props = $props();

  let data = $state<SystemHostMetrics | null>(cachedMetrics);
  let errText = $state('');

  const POLL_MS = 3000;

  function computeLevel(m: SystemHostMetrics | null): Level {
    if (!m) return 'ok';
    const maxPct = Math.max(m.cpu.usage_percent, m.memory.usage_percent, m.disk.usage_percent);
    if (maxPct >= 92) return 'bad';
    if (maxPct >= 80) return 'warn';
    return 'ok';
  }

  function toneFor(pct: number): 'ok' | 'warn' | 'bad' {
    if (pct >= 90) return 'bad';
    if (pct >= 75) return 'warn';
    return 'ok';
  }

  function fmtRate(bps: number): string {
    if (!Number.isFinite(bps) || bps <= 0) return '0 B/s';
    return `${fmtBytes(bps)}/s`;
  }

  function fmtUptime(sec: number): string {
    if (!sec || sec < 60) return '刚刚启动';
    const d = Math.floor(sec / 86400);
    const h = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    if (d > 0) return `${d} 天 ${h} 小时`;
    if (h > 0) return `${h} 小时 ${m} 分钟`;
    return `${m} 分钟`;
  }

  $effect(() => {
    onlevel?.(computeLevel(data));
  });

  $effect(() => {
    let disposed = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let ctrl: AbortController | null = null;

    const paused = () => document.hidden || events.offline;

    async function poll() {
      timer = null;
      if (disposed || paused()) return;
      ctrl = new AbortController();
      try {
        const res = await system.metrics({ signal: ctrl.signal });
        if (disposed) return;
        cachedMetrics = res;
        cachedAt = Date.now();
        data = res;
        errText = '';
      } catch (e) {
        if (!ctrl.signal.aborted && !data) {
          errText = e instanceof Error ? e.message : '监控指标读取失败';
        }
      } finally {
        ctrl = null;
        if (!disposed) {
          timer = setTimeout(poll, POLL_MS);
        }
      }
    }

    const onVis = () => {
      if (!paused() && !timer && !ctrl) void poll();
    };
    document.addEventListener('visibilitychange', onVis);

    const age = Date.now() - cachedAt;
    if (cachedMetrics && age < POLL_MS) {
      timer = setTimeout(poll, Math.max(300, POLL_MS - age));
    } else {
      untrack(() => void poll());
    }

    return () => {
      disposed = true;
      if (timer) clearTimeout(timer);
      ctrl?.abort();
      document.removeEventListener('visibilitychange', onVis);
    };
  });
</script>

<section class="monitor" aria-label="服务器实时资源监控">
  {#if data}
    <div class="host-strip">
      <div class="host-item">
        <Icon name="cpu" size={14} />
        <strong class="mono">{data.host.hostname}</strong>
      </div>
      <span class="sep">·</span>
      <span class="host-meta">{data.host.os}</span>
      <span class="sep">·</span>
      <span class="host-meta mono">{data.host.kernel}</span>
      <span class="sep">·</span>
      <span class="host-meta mono">{data.host.arch}</span>
      <span class="host-up">
        <i class="live-dot" aria-hidden="true"></i>
        已运行 {fmtUptime(data.host.uptime_seconds)}
      </span>
    </div>

    <div class="cards">
      <!-- CPU & 负载 -->
      <article class="m-card">
        <header class="m-head">
          <Tile icon="cpu" color="blue" size="sm" />
          <div class="m-ttl">
            <h3>CPU 处理器</h3>
            <small>{data.cpu.cores} 核 · 负载 {data.cpu.load_1.toFixed(2)} / {data.cpu.load_5.toFixed(2)} / {data.cpu.load_15.toFixed(2)}</small>
          </div>
          <span class="pct num t-{toneFor(data.cpu.usage_percent)}">{data.cpu.usage_percent.toFixed(1)}%</span>
        </header>
        <div class="bar-track" aria-hidden="true">
          <div class="bar-fill t-{toneFor(data.cpu.usage_percent)}" style:width="{Math.min(100, Math.max(2, data.cpu.usage_percent))}%"></div>
        </div>
        <div class="m-foot">
          <span class="muted">1/5/15 分钟平均负载</span>
          {#if data.cpu.history.length > 1}
            <Sparkline points={data.cpu.history} tone="blue" width={104} height={26} />
          {/if}
        </div>
      </article>

      <!-- 内存 & Swap -->
      <article class="m-card">
        <header class="m-head">
          <Tile icon="memory" color="violet" size="sm" />
          <div class="m-ttl">
            <h3>内存占用</h3>
            <small class="num">
              {fmtBytes(data.memory.used_bytes)} / {fmtBytes(data.memory.total_bytes)}
            </small>
          </div>
          <span class="pct num t-{toneFor(data.memory.usage_percent)}">{data.memory.usage_percent.toFixed(1)}%</span>
        </header>
        <div class="bar-track" aria-hidden="true">
          <div class="bar-fill t-{toneFor(data.memory.usage_percent)}" style:width="{Math.min(100, Math.max(2, data.memory.usage_percent))}%"></div>
        </div>
        <div class="m-foot">
          <span class="muted num">
            {#if data.memory.swap_total_bytes > 0}
              Swap {fmtBytes(data.memory.swap_used_bytes)} / {fmtBytes(data.memory.swap_total_bytes)}
            {:else}
              可用 {fmtBytes(data.memory.available_bytes)} · 缓存 {fmtBytes(data.memory.cached_bytes)}
            {/if}
          </span>
          {#if data.memory.history.length > 1}
            <Sparkline points={data.memory.history} tone="violet" width={104} height={26} />
          {/if}
        </div>
      </article>

      <!-- 磁盘空间 -->
      <article class="m-card">
        <header class="m-head">
          <Tile icon="disk" color="teal" size="sm" />
          <div class="m-ttl">
            <h3>磁盘空间 ({data.disk.mount || '/'})</h3>
            <small class="num">
              {fmtBytes(data.disk.used_bytes)} / {fmtBytes(data.disk.total_bytes)}
            </small>
          </div>
          <span class="pct num t-{toneFor(data.disk.usage_percent)}">{data.disk.usage_percent.toFixed(1)}%</span>
        </header>
        <div class="bar-track" aria-hidden="true">
          <div class="bar-fill t-{toneFor(data.disk.usage_percent)}" style:width="{Math.min(100, Math.max(2, data.disk.usage_percent))}%"></div>
        </div>
        <div class="m-foot">
          <span class="muted num">
            剩余 {fmtBytes(Math.max(0, data.disk.total_bytes - data.disk.used_bytes))}
          </span>
          <span class="disk-tag mono">{data.disk.mounts[0]?.device || 'rootfs'}</span>
        </div>
      </article>

      <!-- 网络实时流量 -->
      <article class="m-card">
        <header class="m-head">
          <Tile icon="net" color="orange" size="sm" />
          <div class="m-ttl">
            <h3>网络吞吐</h3>
            <small class="num">
              总计 ↓{fmtBytes(data.network.rx_total_bytes)} · ↑{fmtBytes(data.network.tx_total_bytes)}
            </small>
          </div>
        </header>
        <div class="net-rates">
          <div class="net-col">
            <span class="net-k">↓ 入站下载</span>
            <strong class="net-v num">{fmtRate(data.network.rx_bytes_per_sec)}</strong>
          </div>
          <div class="net-col">
            <span class="net-k">↑ 出站上传</span>
            <strong class="net-v num">{fmtRate(data.network.tx_bytes_per_sec)}</strong>
          </div>
        </div>
        <div class="m-foot">
          <span class="muted">实时速率（每 3 秒更新）</span>
          {#if data.network.tx_history.length > 1 || data.network.rx_history.length > 1}
            {@const net = data.network}
            <Sparkline
              points={net.rx_history.map((v, i) => v + (net.tx_history[i] ?? 0))}
              tone="orange"
              width={104}
              height={26}
            />
          {/if}
        </div>
      </article>
    </div>
  {:else if errText}
    <div class="err-strip">
      <span>{errText}</span>
    </div>
  {:else}
    <div class="cards loading" aria-hidden="true">
      {#each [0, 1, 2, 3] as idx (idx)}
        <div class="m-card placeholder"></div>
      {/each}
    </div>
  {/if}
</section>

<style>
  .monitor {
    display: flex;
    flex-direction: column;
    gap: var(--s-3);
  }
  .host-strip {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    padding: 10px 16px;
    border-radius: var(--r-lg);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-1);
    font-size: var(--fs-xs);
    color: var(--text-2);
  }
  .host-item {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--text);
  }
  .sep {
    color: var(--line-strong);
  }
  .host-meta {
    color: var(--text-2);
  }
  .host-up {
    margin-left: auto;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--ok-text);
    font-weight: var(--fw-medium);
  }
  .live-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--ok);
  }
  .cards {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: var(--gap);
  }
  .m-card {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding: var(--s-4) var(--s-5);
    border-radius: var(--r-lg);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-1);
    min-height: 146px;
    transition:
      box-shadow var(--dur-2) var(--ease),
      border-color var(--dur-2) var(--ease);
  }
  .m-card:hover {
    border-color: var(--line-strong);
    box-shadow: var(--shadow-2);
  }
  .m-card.placeholder {
    background: linear-gradient(90deg, var(--surface) 25%, var(--surface-2) 50%, var(--surface) 75%);
    background-size: 200% 100%;
    animation: qwq-shimmer 1.4s ease-in-out infinite;
  }
  .m-head {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .m-ttl {
    flex: 1;
    min-width: 0;
  }
  .m-ttl h3 {
    margin: 0;
    font-size: var(--fs-md);
    font-weight: var(--fw-semibold);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .m-ttl small {
    display: block;
    color: var(--text-3);
    font-size: var(--fs-xs);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .pct {
    font-size: var(--fs-xl);
    font-weight: var(--fw-bold);
    letter-spacing: -0.02em;
    white-space: nowrap;
  }
  .pct.t-ok {
    color: var(--text);
  }
  .pct.t-warn {
    color: var(--warn-text);
  }
  .pct.t-bad {
    color: var(--bad-text);
  }
  .bar-track {
    height: 7px;
    border-radius: var(--r-pill);
    background: var(--surface-3);
    overflow: hidden;
  }
  .bar-fill {
    height: 100%;
    border-radius: var(--r-pill);
    background: var(--accent);
    transition: width 320ms var(--ease);
  }
  .bar-fill.t-ok {
    background: linear-gradient(90deg, var(--c-blue), var(--c-teal));
  }
  .bar-fill.t-warn {
    background: var(--warn);
  }
  .bar-fill.t-bad {
    background: var(--bad);
  }
  .net-rates {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
  }
  .net-col {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 6px 10px;
    border-radius: var(--r-sm);
    background: var(--surface-2);
  }
  .net-k {
    font-size: var(--fs-2xs);
    color: var(--text-3);
  }
  .net-v {
    font-size: var(--fs-sm);
    font-weight: var(--fw-semibold);
    color: var(--text);
  }
  .m-foot {
    margin-top: auto;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    font-size: var(--fs-xs);
  }
  .disk-tag {
    padding: 2px 7px;
    border-radius: var(--r-pill);
    background: var(--surface-2);
    color: var(--text-3);
    font-size: var(--fs-2xs);
  }
  .err-strip {
    padding: var(--s-4);
    border-radius: var(--r-lg);
    background: var(--surface);
    border: 1px solid var(--line);
    color: var(--text-2);
    font-size: var(--fs-sm);
  }
  @media (max-width: 1220px) {
    .cards {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }
  @media (max-width: 640px) {
    .cards {
      grid-template-columns: minmax(0, 1fr);
    }
    .host-up {
      margin-left: 0;
    }
  }
</style>
