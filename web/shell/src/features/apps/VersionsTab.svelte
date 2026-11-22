<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  VersionsTab · 已保留的版本与回滚（POST /plugins/{id}/rollback，expected_revision）
-->
<script lang="ts">
  import { Button, Card, Chip, ConfirmDialog } from '$ui';
  import { plugins } from '$api/endpoints';
  import type { Plugin } from '$api/types';
  import { describeError } from '$lib/errors';
  import { dateTime, relativeTime } from '$lib/format';
  import { createIntent, type Intent } from '$lib/ops';
  import { session } from '$lib/session.svelte';
  import { toasts } from '$lib/toast.svelte';

  interface Props {
    plugin: Plugin;
    onchanged: () => void;
  }
  let { plugin: p, onchanged }: Props = $props();

  const canUpdate = $derived(session.can('host.plugins:rollback'));
  const canInstall = $derived(session.can('host.plugins:install'));
  const previous = $derived(p.versions.find((v) => !v.active && v.install_status === 'INSTALLED'));

  const STATUS: Record<string, string> = {
    ACTIVE: '使用中',
    STOPPED: '已停止',
    STAGED: '已暂存',
    STARTING: '启动中',
    CANDIDATE: '验证中',
    DRAINING: '切换中',
    REJECTED: '被拒绝',
    ROLLED_BACK: '已回滚',
    QUARANTINED: '已隔离',
  };

  let open = $state(false);
  let err = $state('');
  let intent: Intent = createIntent();

  function ask() {
    err = '';
    intent = createIntent();
    open = true;
  }

  async function rollback() {
    try {
      const r = await plugins.rollback(p.plugin_id, intent.key, p.revision);
      toasts.success(`已回滚到 v${r.to_version}`);
      onchanged();
    } catch (e) {
      err = describeError(e).message;
      throw e;
    }
  }
</script>

<Card title="版本" icon="clock" color="indigo">
  {#snippet actions()}
    {#if canInstall}<Button variant="plain" size="sm" icon="upload" href="/apps/install">上传新版本</Button>{/if}
    {#if canUpdate && previous}<Button variant="soft" size="sm" icon="undo" onclick={ask}>回滚到 v{previous.version}</Button>{/if}
  {/snippet}
  <ol class="versions">
    {#each p.versions as v (v.version)}
      <li>
        <span class="mono strong">v{v.version}</span>
        <Chip size="sm" tone={v.active ? 'ok' : v.status === 'REJECTED' || v.status === 'QUARANTINED' ? 'bad' : 'neutral'}>
          {STATUS[v.status] ?? v.status}
        </Chip>
        <span class="small muted" title={dateTime(v.installed_at)}>安装于 {relativeTime(v.installed_at)}</span>
        {#if v.rejected_reason}<span class="small bad">{v.rejected_reason}</span>{/if}
        <span class="tiny faint mono digest">{v.digest.slice(0, 19)}</span>
      </li>
    {/each}
  </ol>
</Card>

<ConfirmDialog
  bind:open
  title="回滚 {p.name}"
  tone="warn"
  confirmLabel="回滚"
  warning="应用会重启；当前版本的新功能将不可用，设置与数据保留。"
  errorText={err}
  onconfirm={rollback}
>
  {#if previous}从 v{p.active_version} 回滚到 v{previous.version}？{/if}
</ConfirmDialog>

<style>
  .versions {
    display: flex;
    flex-direction: column;
    margin: 0;
    padding: 0;
    list-style: none;
  }
  li {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 12px;
    padding: 12px 0;
  }
  li + li {
    border-top: 1px solid var(--line);
  }
  .digest {
    margin-left: auto;
  }
  .bad {
    color: var(--bad-text);
  }
</style>
