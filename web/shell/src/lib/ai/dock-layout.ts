// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 悬浮窗尺寸（SPEC §4：聊天窗右上角拖拽缩放，min 360×360，max 720×80vh）
 * --------------------------------------------------------------------------
 * 两窗水平居中、同宽；聊天窗底边贴着输入窗上方，故拖拽右上角时：
 *   宽 = 2 × |指针 x − 中线|      高 = 聊天窗底边 − 指针 y
 * 纯函数 + localStorage，便于测试。null 表示"默认尺寸"（宽 720，高度撑满）。
 * ========================================================================== */

export interface DockSize {
  w: number;
  h: number;
}

export const MIN_W = 360;
export const MIN_H = 360;
export const MAX_W = 720;
/** 视口两侧至少留 16 */
const EDGE = 16;
const KEY = 'qwq.dock.size';

export function clampSize(s: DockSize, vw: number, vh: number, maxH = vh * 0.8): DockSize {
  const maxW = Math.max(MIN_W, Math.min(MAX_W, vw - 2 * EDGE));
  const hiH = Math.max(MIN_H, Math.min(vh * 0.8, maxH));
  return {
    w: Math.round(Math.min(maxW, Math.max(Math.min(MIN_W, maxW), s.w))),
    h: Math.round(Math.min(hiH, Math.max(MIN_H, s.h))),
  };
}

/** 拖拽右上角：由指针位置与聊天窗几何得到新尺寸（已钳制） */
export function sizeFromPointer(
  p: { x: number; y: number },
  box: { centerX: number; bottom: number; top: number },
  vw: number,
  vh: number,
): DockSize {
  return clampSize({ w: 2 * Math.abs(p.x - box.centerX), h: box.bottom - p.y }, vw, vh, box.bottom - box.top);
}

export function loadSize(storage: Pick<Storage, 'getItem'> | undefined = globalThis.localStorage): DockSize | null {
  try {
    const v = JSON.parse(storage?.getItem(KEY) ?? 'null') as DockSize | null;
    return v && Number.isFinite(v.w) && Number.isFinite(v.h) ? v : null;
  } catch {
    return null;
  }
}

export function saveSize(s: DockSize | null, storage: Pick<Storage, 'setItem' | 'removeItem'> | undefined = globalThis.localStorage): void {
  try {
    if (s) storage?.setItem(KEY, JSON.stringify(s));
    else storage?.removeItem(KEY);
  } catch {
    /* 隐私模式：忽略 */
  }
}
