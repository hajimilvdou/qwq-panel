// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 组件库共用类型（ui 不依赖 api/lib，这里自带最小定义）
 * ========================================================================== */

/** 分类色：彩色底块只表示"类别"（与插件 widget.color 取值一致） */
export const CATEGORY_COLORS = [
  'blue',
  'indigo',
  'violet',
  'teal',
  'cyan',
  'green',
  'amber',
  'orange',
  'red',
  'pink',
  'slate',
] as const;
export type CategoryColor = (typeof CATEGORY_COLORS)[number];

/** 状态色：只表示状态 */
export type Tone = 'neutral' | 'ok' | 'warn' | 'bad' | 'info' | 'ai' | 'accent';

/** 品牌表情的三种心情 */
export type Mood = 'ok' | 'warn' | 'bad';

export interface Option<V extends string = string> {
  value: V;
  label: string;
  disabled?: boolean;
  /** 禁用原因或补充说明（title / 辅助文字） */
  hint?: string;
}

/** Timeline 的一组（通常是一天）；放在 .ts 里，纯 tsc 也能解析具名导出 */
export interface TimelineGroup<I> {
  key: string;
  label: string;
  items: readonly I[];
}
