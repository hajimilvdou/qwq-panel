// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 组件库入口（SPEC §8 统一模式所需的通用组件；无业务依赖）
 * --------------------------------------------------------------------------
 *   import { Button, Card, Dialog } from '$ui';
 * 约束：本目录不得 import $lib / $api（vitest 有扫描用例守护）。
 * 业务组件（ApprovalCard、SchemaForm、SeriesChart、Timeline）由各功能实现。
 * 本文件只做 re-export，vite.config 声明它无副作用：各组件按实际使用分进对应 chunk。
 * ========================================================================== */
export { default as Avatar } from './Avatar.svelte';
export { default as Button } from './Button.svelte';
export { default as Card } from './Card.svelte';
export { default as Checkbox } from './Checkbox.svelte';
export { default as Chip } from './Chip.svelte';
export { default as ConfirmDialog } from './ConfirmDialog.svelte';
export { default as CopyButton } from './CopyButton.svelte';
export { default as DataTable } from './DataTable.svelte';
export { default as Dialog } from './Dialog.svelte';
export { default as Drawer } from './Drawer.svelte';
export { default as EmptyState } from './EmptyState.svelte';
export { default as ErrorState } from './ErrorState.svelte';
export { default as Field } from './Field.svelte';
export { default as Icon } from './Icon.svelte';
export { default as IconButton } from './IconButton.svelte';
export { default as Input } from './Input.svelte';
export { default as Menu } from './Menu.svelte';
export { default as Markdown } from './Markdown.svelte';
export { default as Mood } from './Mood.svelte';
export { default as Orb } from './Orb.svelte';
export { default as OtpInput } from './OtpInput.svelte';
export { default as Ring } from './Ring.svelte';
export { default as Segmented } from './Segmented.svelte';
export { default as Select } from './Select.svelte';
export { default as Skeleton } from './Skeleton.svelte';
export { default as Sparkline } from './Sparkline.svelte';
export { default as Spinner } from './Spinner.svelte';
export { default as Switch } from './Switch.svelte';
export { default as Tabs } from './Tabs.svelte';
export { default as Tile } from './Tile.svelte';
export { default as Toaster } from './Toaster.svelte';

export type { IconName } from './icons';
export type { CategoryColor, Mood as MoodKind, Option, Tone } from './types';
export { CATEGORY_COLORS } from './types';

/* ---------------------------------------------------------------- F2 新增（fe-c） */
export { default as Alert } from './Alert.svelte';
export { default as QrCode } from './QrCode.svelte';
export { default as SchemaForm } from './SchemaForm.svelte';
export * from './schema-form';

/* F2 新增：图表与时间线（接口见 FOUNDATION.md「F2 新增」） */
export { default as SeriesChart } from './SeriesChart.svelte';
export { default as Timeline } from './Timeline.svelte';
export type { TimelineGroup } from './types';
export type { ChartPoint, ChartSeries } from './chart';
