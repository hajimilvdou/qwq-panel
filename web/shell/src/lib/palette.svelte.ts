// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * ⌘K 命令面板开关（SPEC §5；面板本体由 features/palette 实现）
 * ========================================================================== */

class PaletteState {
  opened = $state(false);
  query = $state('');

  open(query = ''): void {
    this.query = query;
    this.opened = true;
  }
  close(): void {
    this.opened = false;
  }
}

export const palette = new PaletteState();

/** 平台快捷键文案：⌘K / Ctrl K */
export const paletteShortcut = (): string =>
  typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform) ? '⌘K' : 'Ctrl K';
