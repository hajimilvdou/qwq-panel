<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  TelemetryStrip · 对话框下方常驻 Token / 速率 / 上下文状态条
-->
<script lang="ts">
  import { Icon } from '$ui';
  import { formatContextTokens, resolveModelContext } from '$lib/ai/model-context-catalog';
  import type { TelemetryState } from '$lib/ai/transcript';

  interface Props {
    telemetry?: TelemetryState | null;
    model?: string;
    maxContextTokens?: number;
    compact?: boolean;
  }
  let { telemetry = null, model = '', maxContextTokens = 0, compact = false }: Props = $props();

  let pop = $state<'speed' | 'cache' | 'ctx' | null>(null);
  const resolvedCtx = $derived(resolveModelContext(model, maxContextTokens || 0));
  const ctxLimit = $derived(telemetry?.maxContextTokens || resolvedCtx.tokens);
  const ctxUsed = $derived(
    telemetry ? telemetry.systemTokens + telemetry.toolDefTokens + telemetry.messageTokens : 0,
  );
  const ctxPct = $derived(
    telemetry ? telemetry.contextPct : 0,
  );
  const totalTok = $derived(
    telemetry ? telemetry.promptTokens + telemetry.completionTokens : 0,
  );

  function toggle(k: 'speed' | 'cache' | 'ctx') {
    pop = pop === k ? null : k;
  }
</script>

<div class="tstrip" class:compact>
  <span class="m-wrap">
    <button type="button" class="m-btn" class:on={pop === 'speed'} onclick={() => toggle('speed')}>
      <Icon name="clock" size={12} />
      {#if telemetry}
        {telemetry.turns} 轮 {telemetry.steps} 步 · {Math.round(telemetry.tps)} tok/s
      {:else}
        0 tok/s
      {/if}
    </button>
    {#if pop === 'speed'}
      <div class="m-pop">
        <b>响应速度明细</b>
        {#if telemetry}
          <p>首字延迟 TTFT：{telemetry.ttftMs} ms</p>
          <p>模型耗时：{telemetry.modelMs} ms · 工具耗时：{telemetry.toolMs} ms</p>
          <p>输出速率：{telemetry.tps.toFixed(1)} tok/s</p>
        {:else}
          <p>发送首条消息后实时统计首字延迟与生成速率。</p>
        {/if}
      </div>
    {/if}
  </span>

  <span class="m-wrap">
    <button type="button" class="m-btn" class:on={pop === 'cache'} onclick={() => toggle('cache')}>
      Token {totalTok.toLocaleString()}{#if telemetry && telemetry.cachedTokens > 0} · 缓存 {telemetry.cacheHitPct.toFixed(0)}%{/if}
    </button>
    {#if pop === 'cache'}
      <div class="m-pop">
        <b>Token 与缓存用量</b>
        {#if telemetry}
          <p>输入：{telemetry.promptTokens.toLocaleString()} · 输出：{telemetry.completionTokens.toLocaleString()}</p>
          <p>缓存命中：{telemetry.cachedTokens.toLocaleString()} ({telemetry.cacheHitPct.toFixed(1)}%)</p>
        {:else}
          <p>当前尚未消耗 Token（输入 0 · 输出 0）。</p>
        {/if}
      </div>
    {/if}
  </span>

  <span class="m-wrap">
    <button type="button" class="m-btn" class:on={pop === 'ctx'} onclick={() => toggle('ctx')}>
      上下文 {formatContextTokens(ctxUsed)} / {formatContextTokens(ctxLimit)} ({ctxPct.toFixed(0)}%)
    </button>
    {#if pop === 'ctx'}
      <div class="m-pop">
        <b>上下文窗口分布</b>
        {#if telemetry}
          <p>系统提示：{telemetry.systemTokens.toLocaleString()} · 工具定义：{telemetry.toolDefTokens.toLocaleString()}</p>
          <p>会话消息：{telemetry.messageTokens.toLocaleString()} / {ctxLimit.toLocaleString()}</p>
        {:else}
          <p>窗口上限：{ctxLimit.toLocaleString()} tokens（{resolvedCtx.source === 'custom' ? '手动覆盖' : resolvedCtx.profile ? `自动匹配 ${resolvedCtx.profile.family}` : '默认'}）</p>
        {/if}
      </div>
    {/if}
  </span>

  {#if !compact}
    <span class="tip">Enter 发送 · Shift+Enter 换行</span>
  {/if}
</div>

<style>
  .tstrip {
    display: flex;
    align-items: center;
    justify-content: center;
    flex-wrap: wrap;
    gap: 8px;
    min-height: 22px;
  }
  .tstrip.compact {
    justify-content: flex-start;
    padding: 4px 12px 6px;
    border-top: 1px solid var(--line);
    background: var(--surface-2);
    border-radius: 0 0 var(--r-lg) var(--r-lg);
  }
  .m-wrap {
    position: relative;
    display: inline-flex;
  }
  .m-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;
    border-radius: var(--r-pill);
    font-size: var(--fs-xs);
    color: var(--text-3);
    font-variant-numeric: tabular-nums;
  }
  .m-btn:hover,
  .m-btn.on {
    background: var(--surface-2);
    color: var(--text);
  }
  .m-pop {
    position: absolute;
    left: 50%;
    bottom: calc(100% + 8px);
    transform: translateX(-50%);
    z-index: 30;
    min-width: 230px;
    padding: 10px 12px;
    border-radius: var(--r-md);
    background: var(--surface);
    border: 1px solid var(--line-strong);
    box-shadow: var(--shadow-2);
    display: grid;
    gap: 4px;
    font-size: var(--fs-xs);
    color: var(--text-2);
    white-space: nowrap;
  }
  .m-pop b {
    color: var(--text);
    font-weight: var(--fw-semibold);
  }
  .tip {
    font-size: var(--fs-2xs);
    color: var(--text-3);
    margin-left: 6px;
  }
  @media (max-width: 860px) {
    .tip {
      display: none;
    }
  }
</style>
