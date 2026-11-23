// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 登录后运行时接线：事件流 ↔ 缓存失效 ↔ 审批队列 ↔ 操作追踪
 * ========================================================================== */
import { approvals } from '$lib/ai/approvals.svelte';
import { dock } from '$lib/ai/dock.svelte';
import { events } from '$lib/events.svelte';
import { liveOps } from '$lib/operations.svelte';
import { resources } from '$lib/resource.svelte';
import { session } from '$lib/session.svelte';

const INVALIDATING = ['resource.changed', 'operation.updated', 'plugin.*', 'agent.session.*'];

let configured = false;
let offs: (() => void)[] = [];

export function startSignedInRuntime(): void {
  if (!configured) {
    configured = true;
    events.configure({ onUnauthenticated: () => session.expire() });
  }
  events.start();
  offs = [
    liveOps.connect(events),
    approvals.connect(events),
    ...INVALIDATING.map((t) => events.on(t, (e) => resources.handle(e))),
    events.onResync(() => resources.invalidateAll()),
  ];
}

export function stopSignedInRuntime(): void {
  offs.forEach((f) => f());
  offs = [];
  events.stop();
  resources.clear();
  liveOps.clear();
  dock.close();
}
