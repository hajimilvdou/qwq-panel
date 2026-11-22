<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  QrCode · 二维码（SVG 组件，非 data URI；SPEC §6 TOTP 绑定）
  ───────────────────────────────────────────────────────────────
  <QrCode text={otpauthUrl} label="两步验证二维码" />
  深浅主题下都用白底黑块，保证验证器 App 能识别。
-->
<script lang="ts">
  import { encode } from 'uqr';

  interface Props {
    text: string;
    label: string;
    size?: number;
  }
  let { text, label, size = 184 }: Props = $props();

  /* 所有暗模块合成一条 path：每格 "M x y h1 v1 h-1 z" */
  const qr = $derived.by(() => {
    const r = encode(text, { ecc: 'M', border: 2 });
    let d = '';
    r.data.forEach((row, y) =>
      row.forEach((on, x) => {
        if (on) d += `M${x} ${y}h1v1h-1z`;
      }),
    );
    return { d, n: r.size };
  });
</script>

<svg
  class="qr"
  role="img"
  aria-label={label}
  width={size}
  height={size}
  viewBox="0 0 {qr.n} {qr.n}"
  shape-rendering="crispEdges"
>
  <rect width={qr.n} height={qr.n} fill="#fff" />
  <path d={qr.d} fill="#111" />
</svg>

<style>
  .qr {
    display: block;
    border-radius: var(--r-sm);
  }
</style>
