<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Ring · 晶莹液态球形占用仪（role="meter"，定稿 v4 qwq X 风格）
  <Ring value={42} label="CPU 使用率" tone="ok" />
  tone：accent（默认）| ok | warn | bad；size 像素，默认 64
-->
<script lang="ts">
  interface Props {
    value: number;
    label: string;
    max?: number;
    tone?: 'accent' | 'ok' | 'warn' | 'bad';
    size?: number;
  }
  let { value, label, max = 100, tone = 'accent', size = 64 }: Props = $props();

  const pct = $derived(Math.max(0, Math.min(100, max > 0 ? Math.round((value / max) * 100) : 0)));
  const fillPct = $derived(pct > 0 ? Math.max(10, pct) : 0);
</script>

<div
  class="orb-gauge {tone}"
  style:width="{size}px"
  style:height="{size}px"
  role="meter"
  aria-label={label}
  aria-valuemin={0}
  aria-valuemax={max}
  aria-valuenow={value}
>
  <div class="liquid" style:height="{fillPct}%">
    <span class="wave loop" aria-hidden="true"></span>
  </div>
  <span class="gloss" aria-hidden="true"></span>
  <span class="pct num">{pct}%</span>
</div>

<style>
  .orb-gauge {
    position: relative;
    flex: none;
    display: grid;
    place-items: center;
    border-radius: 50%;
    overflow: hidden;
    background: var(--surface-2);
    border: 1px solid color-mix(in oklab, var(--line-strong) 75%, transparent);
    box-shadow:
      inset 0 2px 6px rgb(255 255 255 / 0.55),
      inset 0 -4px 10px color-mix(in oklab, var(--text) 8%, transparent);
    --fill: var(--accent);
  }
  .ok { --fill: var(--ok); }
  .warn { --fill: var(--warn); }
  .bad { --fill: var(--bad); }

  .liquid {
    position: absolute;
    inset: auto 0 0 0;
    background: linear-gradient(
      180deg,
      color-mix(in oklab, var(--fill) 72%, white),
      var(--fill)
    );
    transition: height var(--dur-3) var(--ease);
  }
  .wave {
    position: absolute;
    left: -50%;
    top: -7px;
    width: 200%;
    height: 14px;
    border-radius: 44%;
    background: color-mix(in oklab, var(--fill) 62%, white);
    opacity: 0.72;
    animation: orb-sway 4.2s ease-in-out infinite alternate;
  }
  .gloss {
    position: absolute;
    top: 10%;
    left: 16%;
    width: 44%;
    height: 22%;
    border-radius: 50%;
    background: linear-gradient(180deg, rgb(255 255 255 / 0.72), transparent);
    pointer-events: none;
  }
  .pct {
    position: relative;
    z-index: 1;
    font-size: var(--fs-xs);
    font-weight: var(--fw-bold);
    color: var(--text);
    text-shadow: 0 1px 4px color-mix(in oklab, var(--surface) 88%, transparent);
  }
  @keyframes orb-sway {
    from { transform: translateX(-8%) rotate(-2deg); }
    to { transform: translateX(8%) rotate(2deg); }
  }
</style>
