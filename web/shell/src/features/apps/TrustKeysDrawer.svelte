<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  TrustKeysDrawer · 开发者信任公钥管理抽屉
  ───────────────────────────────────────────────────────────────
  查看官方系统公钥与管理员添加的第三方开发者 Ed25519 公钥，支持即时添加与删除。
  若账号启用了 MFA 且当前会话非新鲜二步态，遇到 MFA_REQUIRED 时在抽屉内提示输入验证码重试。
-->
<script lang="ts">
  import { Alert, Button, Chip, CopyButton, Drawer, Icon, Input, Spinner } from '$ui';
  import { plugins } from '$api/endpoints-plugins';
  import type { PluginTrustKey } from '$api/additions';
  import { describeError } from '$lib/errors';

  interface Props {
    open?: boolean;
    hintKeyId?: string;
    onchanged?: () => void;
  }
  let { open = $bindable(false), hintKeyId = '', onchanged }: Props = $props();

  let items = $state<PluginTrustKey[]>([]);
  let loading = $state(false);
  let loadErr = $state('');

  let label = $state('');
  let pubPem = $state('');
  let saving = $state(false);
  let actionErr = $state('');
  let actionOk = $state('');
  let deletingId = $state('');
  let confirmRemoveId = $state('');

  type PendingMfa =
    | { kind: 'add'; label: string; public_key_pem: string }
    | { kind: 'remove'; keyId: string };
  let pendingMfa = $state<PendingMfa | null>(null);
  let mfaCode = $state('');

  async function loadKeys() {
    loading = true;
    loadErr = '';
    try {
      const res = await plugins.trustKeys();
      items = res.items;
    } catch (err) {
      loadErr = describeError(err).message;
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    if (open) {
      actionErr = '';
      actionOk = '';
      void loadKeys();
    } else {
      pendingMfa = null;
      mfaCode = '';
      confirmRemoveId = '';
    }
  });

  async function submitAdd(code?: string) {
    const cleanLabel = label.trim();
    const cleanPem = pubPem.trim();
    if (!cleanLabel) {
      actionErr = '请填写开发者或组织名称标签';
      return;
    }
    if (!cleanPem.includes('BEGIN PUBLIC KEY')) {
      actionErr = '请粘贴完整的 Ed25519 PKIX 公钥 PEM（含 BEGIN PUBLIC KEY）';
      return;
    }
    saving = true;
    actionErr = '';
    actionOk = '';
    try {
      const created = await plugins.addTrustKey({ label: cleanLabel, public_key_pem: cleanPem }, code);
      label = '';
      pubPem = '';
      pendingMfa = null;
      mfaCode = '';
      actionOk = `已信任公钥 ${created.label}（${created.key_id.slice(0, 22)}…）`;
      await loadKeys();
      onchanged?.();
    } catch (err) {
      const v = describeError(err);
      if (v.code === 'MFA_REQUIRED') {
        pendingMfa = { kind: 'add', label: cleanLabel, public_key_pem: cleanPem };
        actionErr = '此操作需要二步验证，请在下方输入 TOTP 验证码或恢复码后继续。';
      } else {
        mfaCode = '';
        pendingMfa = null;
        actionErr = v.message;
      }
    } finally {
      saving = false;
    }
  }

  async function submitRemove(keyId: string, code?: string) {
    deletingId = keyId;
    confirmRemoveId = '';
    actionErr = '';
    actionOk = '';
    try {
      await plugins.removeTrustKey(keyId, code);
      pendingMfa = null;
      mfaCode = '';
      actionOk = '已移除该自定义开发者信任公钥';
      await loadKeys();
      onchanged?.();
    } catch (err) {
      const v = describeError(err);
      if (v.code === 'MFA_REQUIRED') {
        pendingMfa = { kind: 'remove', keyId };
        actionErr = '移除信任公钥需要二步验证，请在下方输入 TOTP 验证码或恢复码后继续。';
      } else {
        mfaCode = '';
        pendingMfa = null;
        actionErr = v.message;
      }
    } finally {
      deletingId = '';
    }
  }

  async function retryWithMfa() {
    const code = mfaCode.trim();
    if (!pendingMfa || !code) return;
    if (pendingMfa.kind === 'add') {
      await submitAdd(code);
    } else {
      await submitRemove(pendingMfa.keyId, code);
    }
  }
</script>

<Drawer bind:open title="开发者信任公钥管理" side="right">
  <div class="trust-body">
    <p class="small muted intro">
      官方系统公钥位于只读目录 <code class="mono">/etc/qwq/trust</code>；在此添加第三方开发者的 Ed25519 公钥后立即生效，无需重启面板。
    </p>

    {#if hintKeyId}
      <Alert tone="info">
        当前待检包签名指纹：<span class="mono break">{hintKeyId}</span>
      </Alert>
    {/if}

    <form
      class="add-form"
      onsubmit={(e) => {
        e.preventDefault();
        void submitAdd();
      }}
    >
      <h3>添加开发者信任公钥</h3>
      <Input label="开发者 / 组织标签" placeholder="例如：Acme 社区插件" bind:value={label} maxlength={120} required />
      <Input
        label="Ed25519 公钥 PEM"
        multiline
        rows={4}
        mono
        placeholder={'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----'}
        bind:value={pubPem}
        required
      />
      {#if !pendingMfa}
        <div class="form-actions">
          <Button type="submit" variant="primary" size="sm" icon="plus" loading={saving}>添加信任公钥</Button>
        </div>
      {/if}
    </form>

    {#if pendingMfa}
      <form
        class="mfa-box"
        onsubmit={(e) => {
          e.preventDefault();
          void retryWithMfa();
        }}
      >
        <Input
          label="二步验证码（TOTP / 恢复码）"
          mono
          placeholder="输入 6 位动态码或恢复码"
          bind:value={mfaCode}
          autocomplete="one-time-code"
        />
        <div class="mfa-actions">
          <Button variant="plain" size="sm" onclick={() => { pendingMfa = null; mfaCode = ''; }}>取消</Button>
          <Button type="submit" variant="primary" size="sm" loading={saving || !!deletingId}>验证并继续</Button>
        </div>
      </form>
    {/if}

    {#if actionErr}<Alert>{actionErr}</Alert>{/if}
    {#if actionOk}<Alert tone="info">{actionOk}</Alert>{/if}

    <section class="key-list">
      <div class="list-head">
        <h3>已信任公钥 ({items.length})</h3>
        <Button variant="plain" size="sm" icon="refresh" loading={loading} onclick={loadKeys}>刷新</Button>
      </div>
      {#if loadErr}
        <Alert>{loadErr}</Alert>
      {:else if loading && items.length === 0}
        <div class="center"><Spinner /></div>
      {:else if items.length === 0}
        <p class="small muted">尚未配置任何信任公钥。</p>
      {:else}
        <ul>
          {#each items as k (k.key_id)}
            <li class:matched={hintKeyId && k.key_id === hintKeyId}>
              <div class="row-top">
                <span class="key-label">{k.label}</span>
                <Chip tone={k.source === 'official' ? 'ok' : 'info'} size="sm" dot={false}>
                  {k.source === 'official' ? '官方系统' : '自定义'}
                </Chip>
              </div>
              <div class="row-id">
                <code class="mono tiny">{k.key_id.slice(0, 28)}…{k.key_id.slice(-8)}</code>
                <CopyButton text={k.key_id} label="复制 key_id" />
              </div>
              <div class="row-foot">
                <span class="tiny faint">
                  {#if k.source === 'official'}
                    <Icon name="lock" size={12} /> 只读保护
                  {:else}
                    自定义信任{k.added_by ? ` · ${k.added_by}` : ''}
                  {/if}
                </span>
                {#if k.source === 'custom'}
                  {#if confirmRemoveId === k.key_id}
                    <div class="confirm-inline">
                      <Button variant="plain" size="sm" onclick={() => (confirmRemoveId = '')}>取消</Button>
                      <Button
                        variant="danger"
                        size="sm"
                        loading={deletingId === k.key_id}
                        onclick={() => void submitRemove(k.key_id)}
                      >
                        确认移除
                      </Button>
                    </div>
                  {:else}
                    <Button
                      variant="plain"
                      size="sm"
                      icon="trash"
                      loading={deletingId === k.key_id}
                      onclick={() => (confirmRemoveId = k.key_id)}
                    >
                      移除
                    </Button>
                  {/if}
                {/if}
              </div>
            </li>
          {/each}
        </ul>
      {/if}
    </section>
  </div>
</Drawer>

<style>
  .trust-body {
    display: flex;
    flex-direction: column;
    gap: var(--s-4);
    padding: 0 var(--s-2);
  }
  .intro {
    margin: 0;
    line-height: 1.5;
  }
  .break {
    word-break: break-all;
  }
  .add-form {
    display: flex;
    flex-direction: column;
    gap: var(--s-3);
    padding: var(--s-3);
    border: 1px solid var(--line);
    border-radius: var(--r-md);
    background: var(--surface-2);
  }
  .add-form h3,
  .list-head h3 {
    margin: 0;
    font-size: var(--fs-sm);
    font-weight: var(--fw-semibold);
  }
  .form-actions,
  .mfa-actions,
  .confirm-inline {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
  .mfa-box {
    display: flex;
    flex-direction: column;
    gap: var(--s-2);
    padding: var(--s-3);
    border: 1px solid var(--accent);
    border-radius: var(--r-sm);
    background: var(--surface);
  }
  .list-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: var(--s-2);
  }
  .key-list ul {
    display: flex;
    flex-direction: column;
    gap: var(--s-2);
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .key-list li {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 10px 12px;
    border: 1px solid var(--line);
    border-radius: var(--r-md);
    background: var(--surface);
  }
  .key-list li.matched {
    border-color: var(--ok-text);
    background: var(--ok-soft);
  }
  .row-top,
  .row-id,
  .row-foot {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .key-label {
    font-size: var(--fs-sm);
    font-weight: var(--fw-medium);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .row-id code {
    color: var(--text-2);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .row-foot .tiny {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .center {
    display: grid;
    place-items: center;
    padding: var(--s-4);
  }
</style>
