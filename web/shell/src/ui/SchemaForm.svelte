<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  SchemaForm · 按 JSON Schema 生成分组自适应表单（SPEC §3.4 插件设置、§5 ⌘K 动作参数）
  ───────────────────────────────────────────────────────────────
  · 支持 schema 字段声明 x-group / x-group-desc，自动按主题拆分为清晰的分组卡片
  · 宽屏容器下文本/数字/下拉采用 2 列紧凑栅格，窄弹窗内自动回落单列
  · 开关、密文、长文本与 JSON 字段始终通栏排布，阅读与操作一眼清晰
-->
<script lang="ts">
  import Button from './Button.svelte';
  import Field from './Field.svelte';
  import Icon from './Icon.svelte';
  import Input from './Input.svelte';
  import Select from './Select.svelte';
  import Switch from './Switch.svelte';
  import { groupFields, isSecret, type FormValues, type SchemaField } from './schema-form';

  interface Props {
    fields: readonly SchemaField[];
    values: FormValues;
    errors?: Record<string, string>;
    disabled?: boolean;
  }
  let { fields, values = $bindable(), errors = {}, disabled = false }: Props = $props();

  const groups = $derived(groupFields(fields));
  const hasGroups = $derived(groups.some((g) => Boolean(g.title)));

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

  const isWide = (f: SchemaField) => f.kind === 'boolean' || f.kind === 'text' || f.kind === 'json' || f.kind === 'secret';
</script>

{#snippet fieldControl(f: SchemaField)}
  {@const v = values[f.name]}
  {@const err = errors[f.pointer]}
  <div class="sf-item" class:wide={isWide(f)}>
    {#if f.kind === 'boolean'}
      <div class="row-bool">
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
            placeholder={f.placeholder}
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
        placeholder={f.required ? '请选择' : '默认 / 不设置'}
        options={f.options ?? []}
        value={typeof v === 'string' ? v : ''}
        onchange={(e) => (values[f.name] = e.currentTarget.value)}
      />
    {:else}
      <Input
        label={f.label}
        hint={f.kind === 'json' ? [f.hint, 'JSON 格式'].filter(Boolean).join(' · ') : rangeHint(f)}
        placeholder={f.placeholder}
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
  </div>
{/snippet}

<div class="schema-form">
  {#if hasGroups}
    {#each groups as g, gi (g.title ?? `g-${gi}`)}
      <section class="sf-group">
        {#if g.title}
          <header class="sf-ghead">
            <h4>{g.title}</h4>
            {#if g.desc}<p>{g.desc}</p>{/if}
          </header>
        {/if}
        <div class="sf-grid">
          {#each g.fields as f (f.name)}
            {@render fieldControl(f)}
          {/each}
        </div>
      </section>
    {/each}
  {:else}
    <div class="sf-grid">
      {#each fields as f (f.name)}
        {@render fieldControl(f)}
      {/each}
    </div>
  {/if}
</div>

<style>
  .schema-form {
    display: flex;
    flex-direction: column;
    gap: var(--s-4);
  }
  .sf-group {
    display: flex;
    flex-direction: column;
    gap: var(--s-4);
    padding: var(--s-4) var(--s-5);
    border-radius: var(--r-md);
    background: var(--surface-2);
    border: 1px solid var(--line);
  }
  .sf-ghead {
    padding-bottom: 10px;
    border-bottom: 1px solid var(--line);
  }
  .sf-ghead h4 {
    margin: 0;
    font-size: var(--fs-md);
    font-weight: var(--fw-semibold);
    color: var(--text);
  }
  .sf-ghead p {
    margin: 3px 0 0;
    font-size: var(--fs-xs);
    color: var(--text-3);
    line-height: 1.5;
  }
  .sf-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: var(--s-4);
    align-items: start;
  }
  .sf-item {
    min-width: 0;
  }
  .sf-item.wide {
    grid-column: 1 / -1;
  }
  .row-bool {
    padding: 10px 14px;
    border-radius: 12px;
    background: var(--surface);
    border: 1px solid var(--line);
  }
  .row-bool .err {
    margin: 6px 0 0;
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
    background: var(--surface);
    color: var(--text-2);
  }
  .dot {
    color: var(--text-3);
  }
</style>
