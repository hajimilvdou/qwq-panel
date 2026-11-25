<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  SecurityTakeoverBar · 共存防火墙 / 防爆破一键备份接管与还原控制栏
  ──────────────────────────────────────────────────────────────────────────────
  当检测到 ufw / firewalld / fail2ban 处于活跃旁观或已接管状态时，在「基础安全」顶部展示，
  支持一键自动备份原配置 + 保留现有开放端口并接管，以及随时一键还原交回原服务。
-->
<script lang="ts">
  import type { SecurityTakeoverEntry } from '$api/additions';
  import { system } from '$api/endpoints-core';
  import { describeError } from '$lib/errors';
  import { session } from '$lib/session.svelte';
  import { toasts } from '$lib/toast.svelte';
  import { Alert, Button, Chip, ConfirmDialog, Icon } from '$ui';

  interface Props {
    onchanged?: () => void;
  }
  let { onchanged }: Props = $props();

  const isAdmin = $derived(session.role === 'admin');
  let entries = $state<SecurityTakeoverEntry[]>([]);
  let busyMgr = $state<string | null>(null);
  let errMsg = $state('');
  let confirmState = $state<{
    open: boolean;
    mode: 'takeover' | 'restore';
    entry: SecurityTakeoverEntry | null;
  }>({ open: false, mode: 'takeover', entry: null });

  const LABEL: Record<SecurityTakeoverEntry['manager'], string> = {
    ufw: 'UFW 防火墙',
    firewalld: 'firewalld 防火墙',
    fail2ban: 'fail2ban 防爆破',
  };

  const actionable = $derived(
    entries.filter((e) => e.active || e.taken_over || e.backup_exists),
  );

  async function load() {
    if (!isAdmin) return;
    try {
      const res = await system.securityTakeoverStatus();
      entries = res.managers ?? [];
      errMsg = '';
    } catch {
      /* 非特权环境静默忽略 */
    }
  }

  $effect(() => {
    if (isAdmin) void load();
  });

  function ask(mode: 'takeover' | 'restore', entry: SecurityTakeoverEntry) {
    confirmState = { open: true, mode, entry };
  }

  async function execute() {
    const { mode, entry } = confirmState;
    if (!entry) return;
    busyMgr = entry.manager;
    errMsg = '';
    try {
      const res =
        mode === 'takeover'
          ? await system.securityTakeover(entry.manager)
          : await system.securityRestore(entry.manager);
      entries = res.managers ?? [];
      toasts.success(
        mode === 'takeover'
          ? `已备份原配置并接管 ${LABEL[entry.manager]}，下方工作台已切为可操作模式`
          : `已还原 ${LABEL[entry.manager]} 并交回系统控制`,
      );
      onchanged?.();
    } catch (err) {
      errMsg = describeError(err).message;
      throw err;
    } finally {
      busyMgr = null;
    }
  }
</script>

{#if isAdmin && actionable.length > 0}
  <section class="tk-bar" aria-label="防火墙与防爆破接管控制">
    <div class="tk-head">
      <div class="tk-ttl">
        <Icon name="shield" size={16} />
        <strong>一键接管 / 还原系统安全服务</strong>
        <span class="muted">接管前自动备份原配置文件并无损保留现有开放端口；不想由面板管理时可随时一键还原</span>
      </div>
    </div>

    {#if errMsg}
      <Alert tone="bad">{errMsg}</Alert>
    {/if}

    <div class="tk-list">
      {#each actionable as item (item.manager)}
        <div class="tk-item">
          <div class="tk-info">
            <div class="tk-row">
              <strong>{LABEL[item.manager]}</strong>
              {#if item.taken_over}
                <Chip size="sm" tone="ok">已由面板接管</Chip>
              {:else if item.active}
                <Chip size="sm" tone="warn">原程序运行中（旁观模式）</Chip>
              {:else if item.backup_exists}
                <Chip size="sm" tone="info">存在接管备份</Chip>
              {/if}
            </div>
            <span class="tk-sub">
              {item.detail}
              {#if item.imported_ports?.length}
                · 已继承开放端口：{item.imported_ports.join(', ')}
              {/if}
            </span>
          </div>
          <div class="tk-acts">
            {#if item.active}
              <Button
                size="sm"
                variant="primary"
                loading={busyMgr === item.manager}
                disabled={!!busyMgr}
                onclick={() => ask('takeover', item)}
              >
                备份并接管
              </Button>
            {/if}
            {#if item.taken_over || item.backup_exists}
              <Button
                size="sm"
                variant="soft"
                loading={busyMgr === item.manager}
                disabled={!!busyMgr}
                onclick={() => ask('restore', item)}
              >
                还原原程序
              </Button>
            {/if}
          </div>
        </div>
      {/each}
    </div>
  </section>

  <ConfirmDialog
    bind:open={confirmState.open}
    title={confirmState.mode === 'takeover'
      ? `备份并接管 ${confirmState.entry ? LABEL[confirmState.entry.manager] : ''}？`
      : `还原 ${confirmState.entry ? LABEL[confirmState.entry.manager] : ''}？`}
    tone={confirmState.mode === 'takeover' ? 'primary' : 'warn'}
    confirmLabel={confirmState.mode === 'takeover' ? '确认备份并接管' : '确认还原'}
    onconfirm={execute}
  >
    {#if confirmState.mode === 'takeover'}
      系统会先完整备份现有配置文件（并自动提取当前已开放端口合并进面板防火墙，保留 SSH 与面板管理端口不断联），然后停用原服务并由 qwq 接管。后续可随时点击「还原原程序」恢复原状。
    {:else}
      将清理面板接管规则并重新启动原服务，恢复为由原程序管理。
    {/if}
  </ConfirmDialog>
{/if}

<style>
  .tk-bar {
    display: grid;
    gap: 10px;
    padding: 14px 16px;
    margin-bottom: var(--s-4);
    border-radius: var(--r-lg);
    background: var(--surface);
    border: 1px solid var(--line);
    box-shadow: var(--shadow-1);
  }
  .tk-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .tk-ttl {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    font-size: var(--fs-sm);
  }
  .tk-ttl .muted {
    font-size: var(--fs-xs);
  }
  .tk-list {
    display: grid;
    gap: 8px;
  }
  .tk-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 12px;
    padding: 10px 12px;
    border-radius: var(--r-md);
    background: var(--surface-2);
    border: 1px solid var(--line);
  }
  .tk-info {
    display: grid;
    gap: 4px;
    min-width: 0;
  }
  .tk-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .tk-sub {
    font-size: var(--fs-xs);
    color: var(--text-3);
  }
  .tk-acts {
    display: flex;
    align-items: center;
    gap: 8px;
  }
</style>
