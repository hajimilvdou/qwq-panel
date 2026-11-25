// SPDX-License-Identifier: AGPL-3.0-only
/* qwq 首帧脚本：在样式与应用之前设置 <html data-*>，避免主题闪烁。
 * 键与取值必须与 shell/src/lib/prefs.svelte.ts 一致。保持 <1KB、无依赖。 */
(function () {
  var d = document.documentElement;
  function get(k, ok, def) {
    try {
      var v = localStorage.getItem('qwq.' + k);
      return ok.indexOf(v) >= 0 ? v : def;
    } catch (e) {
      return def;
    }
  }
  function mq(q) {
    return !!(window.matchMedia && matchMedia(q).matches);
  }
  var theme = get('theme', ['light', 'dark', 'system'], 'system');
  var motion = get('motion', ['full', 'reduced', 'off', 'system'], 'system');
  d.dataset.theme = theme === 'system' ? (mq('(prefers-color-scheme: dark)') ? 'dark' : 'light') : theme;
  d.dataset.motion = motion === 'system' ? (mq('(prefers-reduced-motion: reduce)') ? 'reduced' : 'full') : motion;
  d.dataset.accent = get('accent', ['sky', 'violet', 'teal', 'coral', 'rose', 'green'], 'rose');
  d.dataset.density = get('density', ['comfortable', 'compact'], 'comfortable');
  d.dataset.layout = get('layout', ['top', 'side'], 'top');
  d.dataset.sideCollapsed = get('sideCollapsed', ['0', '1'], '0');
})();
