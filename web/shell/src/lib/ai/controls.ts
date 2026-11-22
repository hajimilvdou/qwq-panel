// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 会话控制动作（暂停 / 接管 / 切换模式 / 删除）的统一提示与错误处理
 * --------------------------------------------------------------------------
 * Agent 页会话头与悬浮窗输入窗共用，保证两处行为、文案一致（ADR-0004 D9）。
 * ========================================================================== */
import type { PermissionMode } from '$api/types';
import { reportError } from '../errors';
import { liveOps } from '../operations.svelte';
import { navigate } from '../router.svelte';
import { toasts } from '../toast.svelte';
import type { SessionStream } from './session-stream.svelte';
import { MODE_META } from './agent-sessions.svelte';

/** 修订冲突：别处改过会话，重拉后提示再试 */
async function guarded(stream: SessionStream, fn: () => Promise<void>, fail: string): Promise<boolean> {
  try {
    await fn();
    return true;
  } catch (err) {
    if ((err as { code?: string }).code === 'REVISION_CONFLICT') {
      await stream.reload();
      toasts.warn('会话刚被别处改过，已刷新，请再试一次');
    } else reportError(err, fail);
    return false;
  }
}

export const pauseSession = (s: SessionStream) =>
  guarded(s, () => s.cancel(), '暂停没有成功').then((ok) => ok && toasts.info('已暂停，AI 不会继续这一轮'));

export const changeMode = (s: SessionStream, mode: PermissionMode) =>
  guarded(s, () => s.setMode(mode), '切换模式没有成功').then(
    (ok) => ok && toasts.success(`已切换为"${MODE_META[mode].label}"`),
  );

/** 接管：停手 + 只读；最近一次工具调用的操作若声明了 ui_route，跳过去让人继续 */
export async function takeOver(s: SessionStream): Promise<void> {
  if (!(await guarded(s, () => s.takeover(), '接管没有成功'))) return;
  toasts.info('AI 已停手，现在由你操作');
  const lastOp = [...s.transcript.items].reverse().find((x) => x.kind === 'tool' && x.operationId);
  const route = lastOp?.kind === 'tool' && lastOp.operationId ? liveOps.get(lastOp.operationId)?.ui_route : undefined;
  if (route?.startsWith('/') && !route.startsWith('//')) navigate(route);
}
