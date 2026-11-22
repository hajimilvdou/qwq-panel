<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  SchemaForm · 按 JSON Schema 生成表单（SPEC §3.4 插件设置、§5 ⌘K 动作参数）
  ───────────────────────────────────────────────────────────────
  const fields = fieldsOf(schema);
  let values = $state(initialValues(fields, config));
  <SchemaForm {fields} bind:values errors={errs} />
  提交前 validate(fields, values) → 字段错误；通过后 toPayload(fields, values)。

  密文字段：已有值时显示"已设置 · 替换"，点"替换"后出现密码框，可"取消替换"。
  服务端 VALIDATION_FAILED 的 fields['/pointer'] 可直接并进 errors。
-->
<script lang="ts">
  import Button from './Button.svelte';
  import Field from './Field.svelte';
  import Icon from './Icon.svelte';
  import Input from './Input.svelte';
  import Select from './Select.svelte';
  import Switch from './Switch.svelte';
  import { isSecret, type FormValues, type SchemaField } from './schema-form';

  interface Props {
    fields: readonly SchemaField[];
    values: FormValues;
    errors?: Record<string, string>;
    disabled?: boolean;
  }
  let { fields, values = $bindable(), errors = {}, disabled = false }: Props = $props();

  function rangeHint(f: SchemaField): string | undefined {
    const r =
      f.minimum !== undefined && f.maximum !== undefined
        ? `${f.minimum}–${f.maximum}`
        : f.minimum !== undefined
          ? `≥ ${f.minimum}`
          : f.maximum !== undefined
            ? `≤ ${f.maximum}`
            : '';
    return [f.hint, r && `范围 ${r}`].filter(Boolean).join(' · ') || undefined;
  }

  function setSecret(name: string, patch: Partial<{ replacing: boolean; next: string }>) {
    const v = values[name];
    if (isSecret(v)) values[name] = { ...v, ...patch };
  }
</script>

<div class="schema-form">
  {#each fields as f (f.name)}
    {@const v = values[f.name]}
    {@const err = errors[f.pointer]}
    {#if f.kind === 'boolean'}
      <div class="row">
        <Switch
          label={f.label}
          hint={f.hint}
          {disabled}
          checked={v === true}
          onchange={(c) => (values[f.name] = c)}
        />
        {#if err}<p class="err">{err}</p>{/if}
      </div>
    {:else if f.kind === 'secret' && isSecret(v)}
      {#if v.replacing}
        <div class="secret-edit">
          <Input
            label={f.label}
            type="password"
            autocomplete="new-password"
            hint={f.hint}
            error={err}
            required={f.required && v.existing === undefined}
            {disabled}
            value={v.next}
            oninput={(e) => setSecret(f.name, { next: e.currentTarget.value })}
          />
          {#if v.existing !== undefined}
            <Button variant="plain" size="sm" {disabled} onclick={() => setSecret(f.name, { replacing: false, next: '' })}>
              取消替换
            </Button>
          {/if}
        </div>
      {:else}
        <Field label={f.label} hint={f.hint} error={err}>
          {#snippet children({ id, describedby })}
            <div class="secret-set" {id} aria-describedby={describedby}>
              <Icon name="lock" size={16} />
              <span>已设置</span>
              <span class="dot" aria-hidden="true">·</span>
              <Button variant="plain" size="sm" {disabled} onclick={() => setSecret(f.name, { replacing: true })}>
                替换
              </Button>
            </div>
          {/snippet}
        </Field>
      {/if}
    {:else if f.kind === 'enum'}
      <Select
        label={f.label}
        hint={f.hint}
        error={err}
        required={f.required}
        {disabled}
        placeholder={f.required ? '请选择' : '不设置'}
        options={f.options ?? []}
        value={typeof v === 'string' ? v : ''}
        onchange={(e) => (values[f.name] = e.currentTarget.value)}
      />
    {:else}
      <Input
        label={f.label}
        hint={f.kind === 'json' ? [f.hint, 'JSON 格式'].filter(Boolean).join(' · ') : rangeHint(f)}
        error={err}
        required={f.required}
        {disabled}
        multiline={f.kind === 'text' || f.kind === 'json'}
        mono={f.kind === 'json'}
        rows={f.kind === 'json' ? 5 : 3}
        type={f.kind === 'integer' || f.kind === 'number' ? 'number' : f.format === 'uri' ? 'url' : 'text'}
        inputmode={f.kind === 'integer' ? 'numeric' : f.kind === 'number' ? 'decimal' : undefined}
        min={f.minimum}
        max={f.maximum}
        maxlength={f.maxLength}
        value={typeof v === 'string' ? v : ''}
        oninput={(e) => (values[f.name] = e.currentTarget.value)}
      />
    {/if}
  {/each}
</div>

<style>
  .schema-form {
    display: flex;
    flex-direction: column;
    gap: var(--s-4);
  }
  .row .err {
    margin: 4px 0 0;
    color: var(--bad-text);
    font-size: 12px;
  }
  .secret-edit {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 4px;
  }
  .secret-edit > :global(:first-child) {
    align-self: stretch;
  }
  .secret-set {
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: var(--ctl-md);
    padding: 0 6px 0 12px;
    border: 1px dashed var(--line-input);
    border-radius: 12px;
    color: var(--text-2);
  }
  .dot {
    color: var(--text-3);
  }
</style>
