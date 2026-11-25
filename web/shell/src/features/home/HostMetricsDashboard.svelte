<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  HostMetricsDashboard · 主页 C 位内置宿主监控与实时平滑趋势图
  ──────────────────────────────────────────────────────────────────────────────
  直接归属底层框架（GET /api/v1/system/metrics），彻底取代旧版独立基础监控插件：
  · 顶部 4 张核心资源卡（CPU / 内存 / 磁盘 / 网络），剔除无意义的小锯齿图，
    改为悬停/点击展开的实用详情浮层（Top 5 进程占用、状态拆解、全部挂载点、分网卡速率）。
  · 下方直接内置两栏带完整纵横坐标轴、网格线与悬停读数的平滑贝塞尔曲线趋势图。
  · 模块级 + sessionStorage 快照缓冲保证换页/刷新 0ms 瞬显，零白屏闪烁。
-->
<script module lang="ts">
  import type { SystemHostMetrics, SystemHostMetricsPoint, SystemMetricsRange } from '$api/additions';

  let cachedMetrics: SystemHostMetrics | null = null;
  let cachedAt = 0;
  let cachedRange: SystemMetricsRange = '15m';
  const pointsByRange = new Map<SystemMetricsRange, SystemHostMetricsPoint[]>();

  function normalizePoints(res: SystemHostMetrics): SystemHostMetricsPoint[] {
    const byTs = new Map<number, SystemHostMetricsPoint>();
    for (const p of res.history_points ?? []) {
      if (p && typeof p.ts === 'number' && Number.isFinite(p.ts)) byTs.set(p.ts, p);
    }
    const ts = Math.floor(Date.parse(res.collected_at) / 1000) || Math.floor(Date.now() / 1000);
    if (!byTs.has(ts)) {
      byTs.set(ts, {
        ts,
        cpu: res.cpu.usage_percent,
        mem: res.memory.usage_percent,
        rx_bps: res.network.rx_bytes_per_sec,
        tx_bps: res.network.tx_bytes_per_sec,
      });
    }
    return [...byTs.values()].sort((a, b) => a.ts - b.ts);
  }
</script>

<script lang="ts">
  import { untrack } from 'svelte';
  import type { Level } from '$api/additions';
  import { system } from '$api/endpoints-core';
  import { events } from '$lib/events.svelte';
  import { bytes as fmtBytes } from '$lib/format';
  import { Icon, Segmented, Tile } from '$ui';
  import SeriesChart from '$ui/SeriesChart.svelte';

  interface Props {
    onlevel?: (level: Level) => void;
  }
  let { onlevel }: Props = $props();

  const RANGE_OPTS = [
    { value: '5m', label: '5 分钟' },
    { value: '15m', label: '15 分钟' },
    { value: '1h', label: '1 小时' },
    { value: '6h', label: '6 小时' },
    { value: '24h', label: '24 小时' },
  ] as const satisfies readonly { value: SystemMetricsRange; label: string }[];

  let range = $state<SystemMetricsRange>(cachedRange);
  let data = $state<SystemHostMetrics | null>(cachedMetrics);
  let points = $state<SystemHostMetricsPoint[]>(pointsByRange.get(cachedRange) ?? []);
  let errText = $state('');
  let openCard = $state<'cpu' | 'mem' | 'disk' | 'net' | null>(null);
  let pinnedCard = $state<'cpu' | 'mem' | 'disk' | 'net' | null>(null);

  const POLL_MS = 5000;

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

  function showCard(id: 'cpu' | 'mem' | 'disk' | 'net') {
    openCard = id;
  }
  function hideCard(id: 'cpu' | 'mem' | 'disk' | 'net') {
    if (pinnedCard !== id && openCard === id) openCard = null;
  }
  function togglePin(id: 'cpu' | 'mem' | 'disk' | 'net') {
    if (pinnedCard === id) {
      pinnedCard = null;
      openCard = null;
    } else {
      pinnedCard = id;
      openCard = id;
    }
  }

  const cpuMemSeries = $derived([
    {
      name: 'CPU 使用率',
      color: 'blue' as const,
      points: points.map((p) => [p.ts, p.cpu] as const),
    },
    {
      name: '内存占用率',
      color: 'violet' as const,
      points: points.map((p) => [p.ts, p.mem] as const),
    },
  ]);

  const netSeries = $derived([
    {
      name: '入站下载',
      color: 'teal' as const,
      points: points.map((p) => [p.ts, p.rx_bps] as const),
    },
    {
      name: '出站上传',
      color: 'orange' as const,
      points: points.map((p) => [p.ts, p.tx_bps] as const),
    },
  ]);

  $effect(() => {
    onlevel?.(computeLevel(data));
  });

  $effect(() => {
    const activeRange = range;
    cachedRange = activeRange;
    const hit = pointsByRange.get(activeRange);
    if (hit) points = hit;

    let disposed = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let ctrl: AbortController | null = null;
    const paused = () => document.hidden || events.offline;

    async function poll() {
      timer = null;
      if (disposed || paused()) return;
      ctrl = new AbortController();
      try {
        const res = await system.metrics({ range: activeRange, signal: ctrl.signal });
        if (disposed) return;
        const pts = normalizePoints(res);
        cachedMetrics = res;
        cachedAt = Date.now();
        pointsByRange.set(activeRange, pts);
        data = res;
        points = pts;
        errText = '';
      } catch (e) {
        if (!ctrl.signal.aborted && !data) {
          errText = e instanceof Error ? e.message : '监控指标读取失败';
        }
      } finally {
        ctrl = null;
        if (!disposed) {
          const nextDelay = points.length < 2 ? 2000 : POLL_MS;
          timer = setTimeout(poll, nextDelay);
        }
      }
    }

    const onVis = () => {
      if (!paused() && !timer && !ctrl) void poll();
    };
    document.addEventListener('visibilitychange', onVis);

    const age = Date.now() - cachedAt;
    if (cachedMetrics && hit && age < POLL_MS) {
      timer = setTimeout(poll, Math.max(400, POLL_MS - age));
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
    <!-- 主机标识与系统摘要条 -->
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
        已稳定运行 {fmtUptime(data.host.uptime_seconds)}
      </span>
    </div>

    <!-- 顶部 4 张可悬停/点击展开实用详情的核心监控卡 -->
    <div class="cards">
      <!-- 1. CPU 处理器 -->
      <article
        class="m-card"
        class:expanded={openCard === 'cpu'}
        onpointerenter={() => showCard('cpu')}
        onpointerleave={() => hideCard('cpu')}
      >
        <button
          type="button"
          class="card-hit"
          aria-expanded={openCard === 'cpu'}
          onclick={() => togglePin('cpu')}
        >
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
            <span class="muted num">
              用户 {(data.cpu.user_percent ?? 0).toFixed(1)}% · 内核 {(data.cpu.system_percent ?? 0).toFixed(1)}%
              {#if (data.cpu.iowait_percent ?? 0) > 0.1} · IO {(data.cpu.iowait_percent ?? 0).toFixed(1)}%{/if}
            </span>
            <span class="detail-cue">详情</span>
          </div>
        </button>

        {#if openCard === 'cpu'}
          <div class="pop-detail" role="region" aria-label="CPU 占用详情">
            {#if data.cpu.model}
              <p class="pop-sub ellipsis" title={data.cpu.model}>{data.cpu.model}</p>
            {/if}
            <div class="kv-grid">
              <div><span>用户态</span><b class="num">{(data.cpu.user_percent ?? 0).toFixed(1)}%</b></div>
              <div><span>内核态</span><b class="num">{(data.cpu.system_percent ?? 0).toFixed(1)}%</b></div>
              <div><span>IO 等待</span><b class="num">{(data.cpu.iowait_percent ?? 0).toFixed(1)}%</b></div>
              <div><span>空闲</span><b class="num">{Math.max(0, 100 - data.cpu.usage_percent).toFixed(1)}%</b></div>
            </div>
            {#if data.cpu.top_processes?.length}
              <div class="pop-sec">CPU 占用前五任务</div>
              <ul class="proc-list">
                {#each data.cpu.top_processes as pr (pr.pid)}
                  <li>
                    <span class="proc-name ellipsis">{pr.name}</span>
                    <small class="mono muted">#{pr.pid}</small>
                    <b class="num">{pr.cpu_percent.toFixed(1)}%</b>
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
        {/if}
      </article>

      <!-- 2. 内存与 Swap -->
      <article
        class="m-card"
        class:expanded={openCard === 'mem'}
        onpointerenter={() => showCard('mem')}
        onpointerleave={() => hideCard('mem')}
      >
        <button
          type="button"
          class="card-hit"
          aria-expanded={openCard === 'mem'}
          onclick={() => togglePin('mem')}
        >
          <header class="m-head">
            <Tile icon="memory" color="violet" size="sm" />
            <div class="m-ttl">
              <h3>内存占用</h3>
              <small class="num">{fmtBytes(data.memory.used_bytes)} / {fmtBytes(data.memory.total_bytes)}</small>
            </div>
            <span class="pct num t-{toneFor(data.memory.usage_percent)}">{data.memory.usage_percent.toFixed(1)}%</span>
          </header>
          <div class="bar-track" aria-hidden="true">
            <div class="bar-fill violet t-{toneFor(data.memory.usage_percent)}" style:width="{Math.min(100, Math.max(2, data.memory.usage_percent))}%"></div>
          </div>
          <div class="m-foot">
            <span class="muted num">可用 {fmtBytes(data.memory.available_bytes)} · 缓存 {fmtBytes(data.memory.cached_bytes)}</span>
            <span class="detail-cue">详情</span>
          </div>
        </button>

        {#if openCard === 'mem'}
          <div class="pop-detail" role="region" aria-label="内存占用详情">
            <div class="kv-grid">
              <div><span>实际已用</span><b class="num">{fmtBytes(data.memory.used_bytes)}</b></div>
              <div><span>剩余可用</span><b class="num">{fmtBytes(data.memory.available_bytes)}</b></div>
              <div><span>页面缓存</span><b class="num">{fmtBytes(data.memory.cached_bytes)}</b></div>
              <div>
                <span>Swap 交换</span>
                <b class="num">{data.memory.swap_total_bytes > 0 ? `${fmtBytes(data.memory.swap_used_bytes)} / ${fmtBytes(data.memory.swap_total_bytes)}` : '未启用'}</b>
              </div>
            </div>
            {#if data.memory.top_processes?.length}
              <div class="pop-sec">内存占用前五任务</div>
              <ul class="proc-list">
                {#each data.memory.top_processes as pr (pr.pid)}
                  <li>
                    <span class="proc-name ellipsis">{pr.name}</span>
                    <small class="mono muted">{pr.mem_percent.toFixed(1)}%</small>
                    <b class="num">{fmtBytes(pr.mem_bytes)}</b>
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
        {/if}
      </article>

      <!-- 3. 磁盘空间与读写 -->
      <article
        class="m-card"
        class:expanded={openCard === 'disk'}
        onpointerenter={() => showCard('disk')}
        onpointerleave={() => hideCard('disk')}
      >
        <button
          type="button"
          class="card-hit"
          aria-expanded={openCard === 'disk'}
          onclick={() => togglePin('disk')}
        >
          <header class="m-head">
            <Tile icon="disk" color="teal" size="sm" />
            <div class="m-ttl">
              <h3>磁盘空间 ({data.disk.mount || '/'})</h3>
              <small class="num">{fmtBytes(data.disk.used_bytes)} / {fmtBytes(data.disk.total_bytes)}</small>
            </div>
            <span class="pct num t-{toneFor(data.disk.usage_percent)}">{data.disk.usage_percent.toFixed(1)}%</span>
          </header>
          <div class="bar-track" aria-hidden="true">
            <div class="bar-fill teal t-{toneFor(data.disk.usage_percent)}" style:width="{Math.min(100, Math.max(2, data.disk.usage_percent))}%"></div>
          </div>
          <div class="m-foot">
            <span class="muted num">
              剩余 {fmtBytes(Math.max(0, data.disk.total_bytes - data.disk.used_bytes))}
              · 读写 {fmtRate((data.disk.read_bytes_per_sec ?? 0) + (data.disk.write_bytes_per_sec ?? 0))}
            </span>
            <span class="detail-cue">详情</span>
          </div>
        </button>

        {#if openCard === 'disk'}
          <div class="pop-detail" role="region" aria-label="磁盘空间与读写详情">
            <div class="kv-grid">
              <div><span>实时读取</span><b class="num">{fmtRate(data.disk.read_bytes_per_sec ?? 0)}</b></div>
              <div><span>实时写入</span><b class="num">{fmtRate(data.disk.write_bytes_per_sec ?? 0)}</b></div>
            </div>
            {#if data.disk.mounts.length}
              <div class="pop-sec">挂载分区明细（{data.disk.mounts.length}）</div>
              <ul class="proc-list">
                {#each data.disk.mounts.slice(0, 6) as m (m.mount)}
                  <li>
                    <span class="proc-name mono ellipsis" title={m.mount}>{m.mount}</span>
                    <small class="muted num">{fmtBytes(m.used_bytes)} / {fmtBytes(m.total_bytes)}</small>
                    <b class="num">{m.usage_percent.toFixed(0)}%</b>
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
        {/if}
      </article>

      <!-- 4. 网络吞吐与连接 -->
      <article
        class="m-card"
        class:expanded={openCard === 'net'}
        onpointerenter={() => showCard('net')}
        onpointerleave={() => hideCard('net')}
      >
        <button
          type="button"
          class="card-hit"
          aria-expanded={openCard === 'net'}
          onclick={() => togglePin('net')}
        >
          <header class="m-head">
            <Tile icon="net" color="orange" size="sm" />
            <div class="m-ttl">
              <h3>网络吞吐</h3>
              <small class="num">累计 ↓{fmtBytes(data.network.rx_total_bytes)} · ↑{fmtBytes(data.network.tx_total_bytes)}</small>
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
            <span class="muted num">
              活跃 TCP {data.network.tcp_connections ?? 0} 连接
              {#if data.network.interfaces?.[0]} · {data.network.interfaces[0].name}{/if}
            </span>
            <span class="detail-cue">详情</span>
          </div>
        </button>

        {#if openCard === 'net'}
          <div class="pop-detail pop-end" role="region" aria-label="网络接口与连接详情">
            <div class="kv-grid">
              <div><span>活跃 TCP 连接</span><b class="num">{data.network.tcp_connections ?? 0}</b></div>
              <div><span>活跃网卡</span><b class="num">{data.network.interfaces?.length ?? 0} 张</b></div>
            </div>
            {#if data.network.interfaces?.length}
              <div class="pop-sec">物理网卡实时速率</div>
              <ul class="proc-list">
                {#each data.network.interfaces.slice(0, 5) as nic (nic.name)}
                  <li>
                    <span class="proc-name mono">{nic.name}</span>
                    <small class="muted num">↓{fmtRate(nic.rx_bytes_per_sec)}</small>
                    <b class="num">↑{fmtRate(nic.tx_bytes_per_sec)}</b>
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
        {/if}
      </article>
    </div>

    <!-- 内置两栏平滑曲线趋势图（后台 24h 持续采样，切页不中断） -->
    <div class="charts-bar">
      <div class="charts-meta">
        <span class="charts-ttl">实时与历史趋势</span>
        <span class="ch-sub">后台 24 小时持续采集 · 切页不中断</span>
      </div>
      <Segmented size="sm" label="趋势时间窗" options={RANGE_OPTS} bind:value={range} />
    </div>

    <div class="charts-grid">
      <section class="chart-card" aria-label="CPU 与内存实时负载曲线">
        <header class="ch-head">
          <div>
            <h3>CPU 与内存负载趋势</h3>
            <p class="ch-sub">纵轴 0%–100% · 悬停查看任意时间点读数</p>
          </div>
          <span class="rate-chip num">
            CPU {data.cpu.usage_percent.toFixed(1)}% · 内存 {data.memory.usage_percent.toFixed(1)}%
          </span>
        </header>
        <SeriesChart
          label="CPU 与内存实时负载趋势"
          unit="%"
          max={100}
          height={186}
          series={cpuMemSeries}
        />
      </section>

      <section class="chart-card" aria-label="网络实时吞吐趋势">
        <header class="ch-head">
          <div>
            <h3>网络实时网速趋势</h3>
            <p class="ch-sub">物理网卡实时汇总 · 悬停查看上下行速率</p>
          </div>
          <span class="rate-chip num">
            ↓ {fmtRate(data.network.rx_bytes_per_sec)} · ↑ {fmtRate(data.network.tx_bytes_per_sec)}
          </span>
        </header>
        <SeriesChart
          label="网络入站下载与出站上传速率趋势"
          height={186}
          formatValue={fmtRate}
          series={netSeries}
        />
      </section>
    </div>
  {:else if errText}
    <div class="err-strip"><span>{errText}</span></div>
  {:else}
    <div class="cards" aria-hidden="true">
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
    gap: var(--s-4);
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
  .sep { color: var(--line-strong); }
  .host-meta { color: var(--text-2); }
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

  /* ---------------------------------------------------------------- 4 张核心资源卡 */
  .cards {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: var(--gap);
  }
  .m-card {
    position: relative;
    border-radius: var(--r-lg);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-1);
    transition:
      box-shadow var(--dur-2) var(--ease),
      border-color var(--dur-2) var(--ease);
  }
  .m-card:hover,
  .m-card.expanded {
    border-color: var(--line-strong);
    box-shadow: var(--shadow-2);
    z-index: 20;
  }
  .m-card.placeholder {
    min-height: 132px;
    background: linear-gradient(90deg, var(--surface) 25%, var(--surface-2) 50%, var(--surface) 75%);
    background-size: 200% 100%;
    animation: qwq-shimmer 1.4s ease-in-out infinite;
  }
  .card-hit {
    display: flex;
    flex-direction: column;
    gap: 12px;
    width: 100%;
    height: 100%;
    padding: var(--s-4) var(--s-5);
    text-align: left;
    border-radius: inherit;
    cursor: pointer;
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
  .pct.t-ok { color: var(--text); }
  .pct.t-warn { color: var(--warn-text); }
  .pct.t-bad { color: var(--bad-text); }
  .bar-track {
    height: 7px;
    border-radius: var(--r-pill);
    background: var(--surface-3);
    overflow: hidden;
  }
  .bar-fill {
    height: 100%;
    border-radius: var(--r-pill);
    background: linear-gradient(90deg, var(--c-blue), var(--c-cyan));
    transition: width 320ms var(--ease);
  }
  .bar-fill.violet.t-ok { background: linear-gradient(90deg, var(--c-violet), var(--c-indigo)); }
  .bar-fill.teal.t-ok { background: linear-gradient(90deg, var(--c-teal), var(--c-green)); }
  .bar-fill.t-warn { background: var(--warn); }
  .bar-fill.t-bad { background: var(--bad); }
  .net-rates {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
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
  .detail-cue {
    flex: none;
    padding: 2px 8px;
    border-radius: var(--r-pill);
    background: var(--surface-2);
    color: var(--text-3);
    font-size: var(--fs-2xs);
    transition: background-color var(--dur-1) var(--ease), color var(--dur-1) var(--ease);
  }
  .m-card:hover .detail-cue,
  .m-card.expanded .detail-cue {
    background: var(--accent-soft);
    color: var(--accent-text);
  }

  /* ---------------------------------------------------------------- 悬停/展开详情浮层 */
  .pop-detail {
    position: absolute;
    top: calc(100% + 8px);
    left: 0;
    width: max(100%, 300px);
    max-width: min(360px, calc(100vw - 32px));
    padding: 14px 16px;
    border-radius: var(--r-lg);
    background: var(--surface);
    border: 1px solid var(--line-strong);
    box-shadow: var(--shadow-3);
    z-index: 35;
    display: flex;
    flex-direction: column;
    gap: 10px;
    animation: qwq-rise-in var(--dur-1) var(--ease-out);
  }
  .pop-detail::before {
    /* 桥接卡片与浮层间的 8px 间隙，防止鼠标移入浮层时闪退 */
    content: '';
    position: absolute;
    top: -10px;
    left: 0;
    right: 0;
    height: 10px;
  }
  .pop-detail.pop-end {
    left: auto;
    right: 0;
  }
  .pop-sub {
    margin: 0;
    font-size: var(--fs-xs);
    color: var(--text-2);
  }
  .kv-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 8px;
  }
  .kv-grid > div {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 7px 10px;
    border-radius: var(--r-sm);
    background: var(--surface-2);
  }
  .kv-grid span {
    font-size: var(--fs-2xs);
    color: var(--text-3);
  }
  .kv-grid b {
    font-size: var(--fs-sm);
    font-weight: var(--fw-semibold);
    color: var(--text);
  }
  .pop-sec {
    font-size: var(--fs-2xs);
    font-weight: var(--fw-semibold);
    color: var(--text-3);
    padding-top: 2px;
    border-top: 1px solid var(--line);
  }
  .proc-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .proc-list li {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto auto;
    align-items: center;
    gap: 8px;
    font-size: var(--fs-xs);
  }
  .proc-name {
    color: var(--text);
    font-weight: var(--fw-medium);
  }
  .proc-list b {
    color: var(--text);
    font-weight: var(--fw-semibold);
    text-align: right;
  }

  /* ---------------------------------------------------------------- 内置两栏平滑趋势图 */
  .charts-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 10px;
  }
  .charts-meta {
    display: flex;
    align-items: baseline;
    flex-wrap: wrap;
    gap: 8px;
  }
  .charts-ttl {
    font-size: var(--fs-md);
    font-weight: var(--fw-semibold);
  }
  .charts-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: var(--gap);
  }
  .chart-card {
    padding: var(--s-5);
    border-radius: var(--r-lg);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-1);
    min-width: 0;
  }
  .ch-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: var(--s-3);
  }
  .ch-head h3 {
    margin: 0;
    font-size: var(--fs-lg);
    font-weight: var(--fw-semibold);
  }
  .ch-sub {
    margin: 2px 0 0;
    color: var(--text-3);
    font-size: var(--fs-xs);
  }
  .rate-chip {
    display: inline-flex;
    align-items: center;
    padding: 4px 10px;
    border-radius: var(--r-pill);
    background: var(--surface-2);
    color: var(--text-2);
    font-size: var(--fs-xs);
    font-weight: var(--fw-medium);
    white-space: nowrap;
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
    .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .charts-grid { grid-template-columns: minmax(0, 1fr); }
  }
  @media (max-width: 640px) {
    .cards { grid-template-columns: minmax(0, 1fr); }
    .host-up { margin-left: 0; }
    .pop-detail,
    .pop-detail.pop-end {
      left: 0;
      right: 0;
      width: 100%;
    }
  }
</style>
