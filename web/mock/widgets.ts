// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 模拟后端 · 小组件数据与插件静态资源
 * --------------------------------------------------------------------------
 * widgetResult(db, action)  按 action 生成 Stat/Series/Checks/List 形状（随时间平滑变化）
 * pluginAsset(path)         /plugin-ui/{id}/{ver}/… 的示例页：classic script 完成
 *                           plugin.hello → plugin.port → ui.ready 握手（ENG §9）
 * ========================================================================== */
import { BACKUP, MONITOR, SECURITY } from './catalog.ts';
import type { Db } from './store.ts';

const wave = (t: number, period: number, lo: number, hi: number, phase = 0) =>
  lo + ((Math.sin((t / period) * Math.PI * 2 + phase) + 1) / 2) * (hi - lo);

function spark(now: number, period: number, lo: number, hi: number, n = 16): number[] {
  return Array.from({ length: n }, (_, i) => Math.round(wave(now - (n - i) * 5000, period, lo, hi)));
}

const level = (v: number, warn: number, bad: number) => (v >= bad ? 'bad' : v >= warn ? 'warn' : 'ok');

export function widgetResult(db: Db, action: string): unknown {
  const t = Date.now();
  switch (action) {
    case `${MONITOR}/overview.cpu`: {
      const v = Math.round(wave(t, 90_000, 12, 58) + Math.random() * 6);
      return { value: v, unit: '%', sub: '4 核 · 负载 0.82', percent: v, spark: spark(t, 90_000, 12, 58), level: level(v, 80, 95) };
    }
    case `${MONITOR}/overview.memory`: {
      const used = 2.1 + wave(t, 300_000, 0, 0.6);
      const pct = Math.round((used / 4) * 100);
      return { value: used.toFixed(1), unit: 'GB', sub: '共 4 GB', percent: pct, level: level(pct, 85, 95) };
    }
    case `${MONITOR}/overview.disk`: {
      const pct = db.flags.degraded ? 96 : 63;
      return { value: pct, unit: '%', sub: db.flags.degraded ? '只剩 1.6 GB' : '已用 25 / 40 GB', percent: pct, level: level(pct, 85, 95) };
    }
    case `${MONITOR}/overview.network`: {
      const pts = (lo: number, hi: number, ph: number) =>
        Array.from({ length: 30 }, (_, i) => {
          const at = t - (30 - i) * 10_000;
          return [Math.floor(at / 1000), Math.round(wave(at, 120_000, lo, hi, ph) * 10) / 10] as [number, number];
        });
      return { unit: 'MB/s', series: [{ name: '下行', color: 'teal', points: pts(0.4, 6.5, 0) }, { name: '上行', color: 'violet', points: pts(0.1, 1.8, 1.3) }] };
    }
    case `${SECURITY}/overview.checks`: {
      const items = [
        { label: 'SSH 禁止密码登录', value: '已开启', level: 'ok' },
        { label: '防火墙', value: '未开启', level: 'warn' },
        { label: '系统更新', value: db.flags.degraded ? '12 个安全更新' : '已是最新', level: db.flags.degraded ? 'bad' : 'ok' },
        { label: '暴露端口', value: '22, 443', level: 'ok' },
      ];
      return { headline: { value: 312, label: '过去 1 小时被拦截的登录' }, bars: spark(t, 600_000, 2, 40, 12), items };
    }
    case `${SECURITY}/overview.events`:
      return {
        items: [
          { title: '封禁 203.0.113.42', sub: '12 次登录失败', level: 'warn', at: new Date(t - 6 * 60_000).toISOString() },
          { title: '封禁 198.51.100.7', sub: '自动封禁', level: 'warn', at: new Date(t - 52 * 60_000).toISOString() },
          { title: 'alice 登录', sub: '来自 192.0.2.10', level: 'ok', at: new Date(t - 3 * 3600_000).toISOString() },
        ],
      };
    case `${BACKUP}/overview.recent`:
      return {
        items: [
          { title: '每日备份', sub: '412 MB · 用时 38 秒', level: 'ok', at: new Date(t - 7 * 3600_000).toISOString() },
          { title: '每日备份', sub: '409 MB · 用时 41 秒', level: 'ok', at: new Date(t - 31 * 3600_000).toISOString() },
        ],
      };
    default:
      return {};
  }
}

/* ------------------------------------------------------------------ 插件静态资源 */

const PAGE = (title: string) => `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>${title}</title>
<link rel="stylesheet" href="app.css"></head>
<body><main><h1>${title}</h1><p id="status">正在连接面板…</p>
<p class="muted">这是模拟后端提供的插件示例页，用于验证 iframe 握手、主题同步与桥接调用。</p>
<button id="ping" type="button">调用只读操作</button><pre id="out"></pre></main>
<script src="app.js"></script></body></html>`;

const CSS = `body{margin:0;font:14px/1.6 system-ui,sans-serif;color:#1b2232;background:#fff}
main{padding:20px}h1{font-size:18px;margin:0 0 8px}.muted{color:#5f687d}
body.dark{color:#e8ecf4;background:#131a26}body.dark .muted{color:#8791a6}
button{height:36px;padding:0 14px;border:0;border-radius:10px;background:#2f5bd6;color:#fff;font:inherit}
pre{white-space:pre-wrap;font-size:12px}`;

/* classic script：沙箱 iframe（无 allow-same-origin）内模块脚本会走 CORS，故不用 type=module */
const JS = `(function(){var port=null,seq=0,status=document.getElementById('status');
window.addEventListener('message',function(e){var d=e.data||{};if(d.t==='plugin.port'&&e.ports&&e.ports[0]){port=e.ports[0];
port.onmessage=function(m){var x=m.data||{};if(x.t==='ui.settings'){document.body.classList.toggle('dark',x.theme==='dark');}
if(x.t==='api.result'){document.getElementById('out').textContent=JSON.stringify(x,null,2);}};
port.postMessage({t:'ui.ready'});port.postMessage({t:'ui.resize',height:document.body.scrollHeight});status.textContent='已连接面板';}});
document.getElementById('ping').onclick=function(){if(port)port.postMessage({t:'api.invoke',id:String(++seq),operation:'overview.cpu',payload:{}});};
parent.postMessage({t:'plugin.hello',kit_major:1},'*');})();`;

const ICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48"><rect width="48" height="48" rx="14" fill="#5c6bf2"/><path d="M14 30l7-8 5 5 8-10" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

export const PLUGIN_UI_CSP =
  "sandbox allow-scripts allow-forms allow-downloads; default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'";

export function pluginAsset(db: Db, pluginId: string, version: string, file: string): { type: string; body: string } | null {
  const p = db.plugins.get(pluginId);
  if (!p || !p.versions.some((v) => v.version === version)) return null;
  switch (file) {
    case 'index.html':
      return { type: 'text/html; charset=utf-8', body: PAGE(p.name) };
    case 'app.js':
      return { type: 'text/javascript; charset=utf-8', body: JS };
    case 'app.css':
      return { type: 'text/css; charset=utf-8', body: CSS };
    case 'icon.svg':
    case 'assets/icon.svg':
      return { type: 'image/svg+xml', body: ICON };
    default:
      return null;
  }
}
