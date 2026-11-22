<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  设置 · 系统（SPEC §7 / GAPS 缺口 7，host.system:read）
  版本、运行角色、TLS 状态与指纹、监听地址（listen / data_dir 仅管理员可见，后端裁剪）。
-->
<script lang="ts">
  import { Card, Chip, CopyButton, ErrorState, Skeleton } from '$ui';
  import { system } from '$api/endpoints';
  import { describeError } from '$lib/errors';
  import { dateTime, relativeTime } from '$lib/format';
  import { useResource } from '$lib/resource.svelte';

  const info = useResource({ key: 'system.info', load: () => system.info() });

  const ROLE: Record<string, string> = { standalone: '单机', controller: '控制节点', agent: '被控节点' };
  const TLS: Record<string, string> = { self_signed: '自签名证书', acme: '自动签发（ACME）', proxy: '由反向代理终止' };
</script>

{#if info.status === 'loading'}
  <Card title="系统" icon="cpu" color="slate"><Skeleton lines={5} height={16} /></Card>
{:else if info.status === 'error' && !info.data}
  <Card title="系统" icon="cpu" color="slate">
    <ErrorState compact message={describeError(info.error).message} requestId={describeError(info.error).requestId} onretry={info.refresh} />
  </Card>
{:else if info.data}
  {@const s = info.data}
  <Card title="面板" icon="cpu" color="slate">
    <dl class="kv">
      <dt>版本</dt>
      <dd><span class="mono">{s.version}</span>{#if s.commit}<span class="faint mono"> · {s.commit.slice(0, 12)}</span>{/if}</dd>
      <dt>运行角色</dt>
      <dd>{ROLE[s.role] ?? s.role}</dd>
      <dt>启动于</dt>
      <dd title={dateTime(s.started_at)}>{relativeTime(s.started_at)}</dd>
      <dt>应用</dt>
      <dd><Chip size="sm" tone={s.plugins_enabled ? 'ok' : 'neutral'}>{s.plugins_enabled ? '已启用' : '未启用'}</Chip></dd>
      {#if s.listen}<dt>监听地址</dt><dd class="mono">{s.listen}</dd>{/if}
      {#if s.data_dir}<dt>数据目录</dt><dd class="mono">{s.data_dir}</dd>{/if}
    </dl>
  </Card>

  <Card title="TLS" icon="lock" color="green">
    <dl class="kv">
      <dt>模式</dt>
      <dd>{TLS[s.tls.mode] ?? s.tls.mode}</dd>
      {#if s.tls.domains?.length}<dt>域名</dt><dd class="mono">{s.tls.domains.join('、')}</dd>{/if}
      {#if s.tls.not_after}<dt>到期</dt><dd>{dateTime(s.tls.not_after)}</dd>{/if}
      {#if s.tls.fingerprint}
        <dt>证书指纹</dt>
        <dd class="fp"><code class="mono">{s.tls.fingerprint}</code><CopyButton text={s.tls.fingerprint} label="复制指纹" /></dd>
      {/if}
    </dl>
  </Card>
{/if}

<style>
  .kv {
    display: grid;
    grid-template-columns: 112px minmax(0, 1fr);
    gap: var(--s-3) var(--s-4);
    margin: 0;
  }
  dt {
    color: var(--text-3);
  }
  dd {
    margin: 0;
    min-width: 0;
    word-break: break-all;
  }
  .fp {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .fp code {
    font-size: var(--fs-xs);
  }
</style>
