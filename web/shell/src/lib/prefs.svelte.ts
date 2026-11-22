// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 偏好：主题 / 主题色 / 动效 / 密度
 * --------------------------------------------------------------------------
 * 存 localStorage（键 qwq.*），作用到 <html data-*>。首帧由 public/boot.js
 * 用同一套键先行设置，避免闪烁；两边的键名与取值必须一致。
 *
 *   theme   light | dark | system      → data-theme   light | dark
 *   accent  sky | violet | teal | coral | rose | green → data-accent
 *   motion  full | reduced | off | system → data-motion full | reduced | off
 *   density comfortable | compact      → data-density
 * ========================================================================== */

export const THEMES = ['light', 'dark', 'system'] as const;
export const ACCENTS = ['sky', 'violet', 'teal', 'coral', 'rose', 'green'] as const;
export const MOTIONS = ['full', 'reduced', 'off', 'system'] as const;
export const DENSITIES = ['comfortable', 'compact'] as const;
export const LAYOUTS = ['side', 'top'] as const;

export type ThemePref = (typeof THEMES)[number];
export type Accent = (typeof ACCENTS)[number];
export type MotionPref = (typeof MOTIONS)[number];
export type Density = (typeof DENSITIES)[number];
export type LayoutPref = (typeof LAYOUTS)[number];

interface Prefs {
  theme: ThemePref;
  accent: Accent;
  motion: MotionPref;
  density: Density;
  layout: LayoutPref;
}

const DEFAULTS: Prefs = { theme: 'system', accent: 'rose', motion: 'system', density: 'comfortable', layout: 'side' };
const KEY = (k: keyof Prefs) => `qwq.${k}`;

function read<K extends keyof Prefs>(k: K, allowed: readonly Prefs[K][]): Prefs[K] {
  try {
    const v = localStorage.getItem(KEY(k)) as Prefs[K] | null;
    return v && allowed.includes(v) ? v : DEFAULTS[k];
  } catch {
    return DEFAULTS[k];
  }
}

const media = (q: string) => (typeof matchMedia === 'function' ? matchMedia(q) : null);

class PrefsStore {
  theme = $state<ThemePref>(DEFAULTS.theme);
  accent = $state<Accent>(DEFAULTS.accent);
  motion = $state<MotionPref>(DEFAULTS.motion);
  density = $state<Density>(DEFAULTS.density);
  layout = $state<LayoutPref>(DEFAULTS.layout);

  /** 系统偏好（跟随系统时生效），由媒体查询驱动 */
  #systemDark = $state(false);
  #systemReduced = $state(false);

  /** 实际生效值 */
  readonly resolvedTheme = $derived<'light' | 'dark'>(
    this.theme === 'system' ? (this.#systemDark ? 'dark' : 'light') : this.theme,
  );
  readonly resolvedMotion = $derived<'full' | 'reduced' | 'off'>(
    this.motion === 'system' ? (this.#systemReduced ? 'reduced' : 'full') : this.motion,
  );

  /** 读取存储并监听系统变化；main.ts 启动时调用一次 */
  init(): void {
    this.theme = read('theme', THEMES);
    this.accent = read('accent', ACCENTS);
    this.motion = read('motion', MOTIONS);
    this.density = read('density', DENSITIES);
    this.layout = read('layout', LAYOUTS);
    const dark = media('(prefers-color-scheme: dark)');
    const reduced = media('(prefers-reduced-motion: reduce)');
    this.#systemDark = dark?.matches ?? false;
    this.#systemReduced = reduced?.matches ?? false;
    dark?.addEventListener('change', (e) => (this.#systemDark = e.matches));
    reduced?.addEventListener('change', (e) => (this.#systemReduced = e.matches));
  }

  set<K extends keyof Prefs>(k: K, v: Prefs[K]): void {
    (this as unknown as Prefs)[k] = v;
    try {
      localStorage.setItem(KEY(k), v);
    } catch {
      /* 隐私模式：只在内存生效 */
    }
  }

  toggleTheme(): void {
    this.set('theme', this.resolvedTheme === 'dark' ? 'light' : 'dark');
  }

  toggleLayout(): void {
    this.set('layout', this.layout === 'top' ? 'side' : 'top');
  }

  /** 把当前值写到 <html>；由根组件的 $effect 驱动 */
  apply(root: HTMLElement = document.documentElement): void {
    root.dataset.theme = this.resolvedTheme;
    root.dataset.accent = this.accent;
    root.dataset.motion = this.resolvedMotion;
    root.dataset.density = this.density;
    root.dataset.layout = this.layout;
  }
}

export const prefs = new PrefsStore();
