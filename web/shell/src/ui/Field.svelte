<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Field · 表单字段外壳：标签 + 控件 + 提示/错误（负责 id 与 aria 关联）
  ───────────────────────────────────────────────────────────────
  内置控件（Input / Select / Switch）已自带 Field；自定义控件这样用：

  <Field label="角色" error={errs['/role']}>
    {#snippet children({ id, describedby, invalid })}
      <MyControl {id} aria-describedby={describedby} aria-invalid={invalid} />
    {/snippet}
  </Field>
-->
<script lang="ts">
  import type { Snippet } from 'svelte';

  export interface FieldCtx {
    id: string;
    describedby: string | undefined;
    invalid: boolean;
  }

  interface Props {
    label?: string;
    hint?: string;
    error?: string;
    required?: boolean;
    /** 标签视觉隐藏（仍供读屏） */
    hideLabel?: boolean;
    id?: string;
    children: Snippet<[FieldCtx]>;
  }
  let { label, hint, error, required = false, hideLabel = false, id: given, children }: Props = $props();

  const uid = $props.id();
  const id = $derived(given ?? uid);
  const describedby = $derived([error && `${id}-err`, hint && `${id}-hint`].filter(Boolean).join(' ') || undefined);
</script>

<div class="field" class:invalid={!!error}>
  {#if label}
    <label for={id} class:sr-only={hideLabel}>
      {label}{#if required}<span class="req" aria-hidden="true">*</span>{/if}
    </label>
  {/if}
  {@render children({ id, describedby, invalid: !!error })}
  {#if error}
    <p id="{id}-err" class="msg err" role="alert">{error}</p>
  {:else if hint}
    <p id="{id}-hint" class="msg">{hint}</p>
  {/if}
</div>

<style>
  .field {
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-width: 0;
  }
  label {
    font-size: var(--fs-sm);
    font-weight: var(--fw-semibold);
    color: var(--text);
  }
  .req {
    margin-left: 2px;
    color: var(--bad-text);
  }
  .msg {
    font-size: var(--fs-xs);
    color: var(--text-3);
  }
  .err {
    color: var(--bad-text);
  }
</style>
