// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 视觉预览 · 交互脚本
 * --------------------------------------------------------------------------
 * 只服务于静态预览：主题 / 主题色 / 状态切换、图表路径生成、实时数据模拟。
 * 状态写在 URL 查询参数中（?theme=dark&accent=violet&mood=bad），便于分享与截图。
 * 不使用 innerHTML；页面隐藏时暂停全部计时器。
 * ========================================================================== */
(() => {
  "use strict";

  const root = document.documentElement;
  const $ = (sel, el = document) => el.querySelector(sel);
  const $$ = (sel, el = document) => Array.from(el.querySelectorAll(sel));

  /* ------------------------------------------------------------------ 状态 */
  const CHOICES = {
    theme: ["light", "dark"],
    accent: ["sky", "violet", "teal", "coral", "rose", "green"],
    mood: ["ok", "warn", "bad"],
  };
  const MOODS = {
    ok: { face: "happy", title: "一切安好", sub: "已稳定运行 23 天 · 刚刚检查过", count: 0, disk: 62, diskSub: "38 / 61 GB", ai: false },
    warn: { face: "meh", title: "有 2 件事等你确认", sub: "已稳定运行 23 天 · 刚刚检查过", count: 2, disk: 62, diskSub: "38 / 61 GB", ai: true },
    bad: { face: "sad", title: "磁盘快满了，需要处理", sub: "根分区只剩 3.6 GB · AI 助手可以帮你清理", count: 3, disk: 94, diskSub: "57.4 / 61 GB", ai: true },
  };

  const params = new URLSearchParams(location.search);
  const state = {};
  for (const [key, values] of Object.entries(CHOICES)) {
    const v = params.get(key);
    state[key] = values.includes(v) ? v : root.dataset[key];
  }

  function apply() {
    root.dataset.theme = state.theme;
    root.dataset.accent = state.accent;
    root.dataset.mood = state.mood;
    for (const group of $$(".pv-group")) {
      for (const btn of $$("button", group)) {
        btn.setAttribute("aria-pressed", String(btn.dataset.v === state[group.dataset.pv]));
      }
    }
    applyMood(MOODS[state.mood]);
    try {
      history.replaceState(null, "", "?" + new URLSearchParams(state).toString());
    } catch {
      /* 部分浏览器在 file:// 下禁止改写地址，忽略即可 */
    }
  }

  function applyMood(m) {
    for (const use of $$("use[data-face]")) use.setAttribute("href", "#face-" + m.face);
    $("#hero-title").textContent = m.title;
    $("#hero-sub").textContent = m.sub;
    for (const el of $$("[data-attn-count]")) {
      el.textContent = String(m.count);
      el.hidden = m.count === 0;
    }
    $("[data-disk]").textContent = String(m.disk);
    $("[data-disk-sub]").textContent = m.diskSub;
    const diskRing = $('[data-ring="disk"]');
    diskRing.dataset.tone = m.disk > 90 ? "--bad" : "--c-teal";
    setTone(diskRing);
    diskRing.style.setProperty("--v", String(m.disk));
    $(".ai-banner").hidden = !m.ai;
    $(".dock b").textContent = m.ai ? "AI 助手正在工作" : "AI 助手";
    $(".dock small").textContent = m.ai ? "第 2/5 步 · 等你批准" : "有事随时叫我";
  }

  /* ------------------------------------------------------------------ 颜色绑定 */
  function setTone(el) {
    el.style.setProperty("--tone", "var(" + el.dataset.tone + ")");
  }
  $$("[data-tone]").forEach(setTone);
  $$("[data-sw]").forEach((el) => el.style.setProperty("--sw", el.dataset.sw));

  /* ------------------------------------------------------------------ 数据 */
  function rng(seed) {
    return () => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function walker(base, amp, seed) {
    const r = rng(seed);
    let v = base;
    return () => {
      v += (r() - 0.5) * amp + (base - v) * 0.12;
      return Math.max(3, Math.min(97, v));
    };
  }
  function series(n, next) {
    return Array.from({ length: n }, next);
  }

  /* 三次样条平滑路径（Catmull-Rom → Bézier） */
  function smooth(points) {
    let d = "M" + points[0][0].toFixed(1) + "," + points[0][1].toFixed(1);
    for (let i = 0; i < points.length - 1; i++) {
      const p0 = points[i - 1] || points[i];
      const p1 = points[i];
      const p2 = points[i + 1];
      const p3 = points[i + 2] || p2;
      const c1 = [p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6];
      const c2 = [p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6];
      d += " C" + [c1, c2, p2].map((p) => p[0].toFixed(1) + "," + p[1].toFixed(1)).join(" ");
    }
    return d;
  }
  function toPoints(values, w, h, pad) {
    const step = w / (values.length - 1);
    return values.map((v, i) => [i * step, h - pad - (v / 100) * (h - pad * 2)]);
  }

  /* ------------------------------------------------------------------ 图表 */
  const nextCpu = walker(24, 14, 7);
  const nextMem = walker(41, 3, 11);
  const nextNet = walker(45, 30, 5);
  const cpu = series(60, nextCpu);
  const mem = series(60, nextMem);
  const net = series(28, nextNet);

  function drawChart(key, values) {
    const line = smooth(toPoints(values, 600, 190, 12));
    $('[data-line="' + key + '"]').setAttribute("d", line);
    $('[data-area="' + key + '"]').setAttribute("d", line + " L600,190 L0,190 Z");
  }
  function drawSpark() {
    $("[data-spark]").setAttribute("d", smooth(toPoints(net, 112, 44, 4)));
  }
  function drawCpuNow() {
    const now = Math.round(cpu[cpu.length - 1]);
    $$("[data-cpu]").forEach((el) => (el.textContent = String(now)));
    $('[data-ring="cpu"]').style.setProperty("--v", String(now));
  }

  for (const ring of $$("[data-ring]")) {
    const v = Number(ring.dataset.ring);
    if (!Number.isNaN(v)) ring.style.setProperty("--v", String(v));
  }
  const bars = $("[data-bars]");
  const nextBar = walker(35, 40, 3);
  for (let i = 0; i < 24; i++) {
    const s = document.createElement("span");
    s.style.setProperty("--h", String(Math.round(nextBar())));
    bars.append(s);
  }

  /* ------------------------------------------------------------------ 倒计时 */
  const CD_TOTAL = 120;
  let cdLeft = 112;
  function drawCountdown() {
    const m = Math.floor(cdLeft / 60);
    const s = String(cdLeft % 60).padStart(2, "0");
    $("[data-cd]").textContent = m + ":" + s;
    $(".countdown svg").style.setProperty("--v", String((cdLeft / CD_TOTAL) * 100));
  }

  /* ------------------------------------------------------------------ 时钟 */
  let timers = [];
  function start() {
    stop();
    timers.push(
      setInterval(() => {
        cpu.shift();
        cpu.push(nextCpu());
        mem.shift();
        mem.push(nextMem());
        net.shift();
        net.push(nextNet());
        drawChart("cpu", cpu);
        drawChart("mem", mem);
        drawSpark();
        drawCpuNow();
      }, 2000),
      setInterval(() => {
        cdLeft = cdLeft > 0 ? cdLeft - 1 : CD_TOTAL;
        drawCountdown();
      }, 1000),
    );
  }
  function stop() {
    timers.forEach(clearInterval);
    timers = [];
  }
  document.addEventListener("visibilitychange", () => (document.hidden ? stop() : start()));

  /* ------------------------------------------------------------------ 事件 */
  $(".pv").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-v]");
    if (!btn) return;
    state[btn.parentElement.dataset.pv] = btn.dataset.v;
    apply();
  });
  $("#theme-btn").addEventListener("click", () => {
    state.theme = state.theme === "dark" ? "light" : "dark";
    apply();
  });
  for (const seg of $$(".seg")) {
    seg.addEventListener("click", (e) => {
      const btn = e.target.closest("button");
      if (!btn) return;
      $$("button", seg).forEach((b) => b.setAttribute("aria-pressed", String(b === btn)));
    });
  }

  /* ------------------------------------------------------------------ 首帧 */
  drawChart("cpu", cpu);
  drawChart("mem", mem);
  drawSpark();
  drawCpuNow();
  drawCountdown();
  apply();
  if (!document.hidden) start();
})();
