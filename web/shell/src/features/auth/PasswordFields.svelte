<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  PasswordFields · 新口令 + 确认 + 实时策略提示（初始化、注册、改密码共用）
  ───────────────────────────────────────────────────────────────
  <PasswordFields bind:password bind:valid serverError={errs['/password']} />
  valid = 策略满足且两次一致；后端仍是唯一裁决。
-->
<script lang="ts">
  import { Icon, Input } from '$ui';
  import { checkPassword } from './password';

  interface Props {
    password?: string;
    valid?: boolean;
    label?: string;
    serverError?: string;
    disabled?: boolean;
  }
  let { password = $bindable(''), valid = $bindable(false), label = '密码', serverError, disabled = false }: Props = $props();

  let confirm = $state('');
  let touched = $state(false);
  const check = $derived(checkPassword(password));
  const mismatch = $derived(touched && confirm.length > 0 && confirm !== password);

  $effect(() => {
    valid = check.ok && confirm === password;
  });
</script>

<Input {label} type="password" autocomplete="new-password" required {disabled} bind:value={password} error={serverError} />
<ul class="rules" aria-label="密码要求">
  {#each check.rules as r (r.label)}
    <li class:ok={r.ok}>
      <Icon name={r.ok ? 'check-circle' : 'info'} size={14} />
      <span>{r.label}</span>
      <span class="sr-only">{r.ok ? '（已满足）' : '（未满足）'}</span>
    </li>
  {/each}
</ul>
<Input
  label="再输一次"
  type="password"
  autocomplete="new-password"
  required
  {disabled}
  bind:value={confirm}
  onblur={() => (touched = true)}
  error={mismatch ? '两次输入不一致' : undefined}
/>

<style>
  .rules {
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin: calc(var(--s-2) * -1) 0 0;
    padding: 0;
    list-style: none;
    color: var(--text-3);
    font-size: var(--fs-xs);
  }
  li {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  li.ok {
    color: var(--ok-text);
  }
</style>
