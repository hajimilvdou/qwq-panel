<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  DataTable · 数据表格（审计、用户、委托等）
  ───────────────────────────────────────────────────────────────
  <DataTable caption="审计记录" columns={[
      { key: 'at', label: '时间', width: '180px' },
      { key: 'actor', label: '行为人' },
      { key: 'id', label: 'ID', mono: true },
    ]} rows={items} rowKey={(r) => r.audit_id}>
    {#snippet cell(row, key)}{#if key === 'at'}{relativeTime(row.at)}{:else}{row[key]}{/if}{/snippet}
  </DataTable>

  不给 cell 时按 String(row[key]) 渲染（纯文本）。
  loading：显示骨架行；rows 为空且不在加载时渲染 empty 片段。
  窄屏横向滚动，不挤压列。
-->
<script lang="ts" generics="R extends Record<string, unknown>">
  import type { Snippet } from 'svelte';
  import Skeleton from './Skeleton.svelte';

  interface Column {
    key: string;
    label: string;
    width?: string;
    align?: 'start' | 'end' | 'center';
    mono?: boolean;
  }
  interface Props {
    columns: readonly Column[];
    rows: readonly R[];
    rowKey: (row: R) => string;
    caption: string;
    /** 视觉隐藏 caption（仍供读屏） */
    hideCaption?: boolean;
    loading?: boolean;
    cell?: Snippet<[R, string]>;
    empty?: Snippet;
  }
  let { columns, rows, rowKey, caption, hideCaption = true, loading = false, cell, empty }: Props = $props();
</script>

<div class="wrap">
  <table>
    <caption class:sr-only={hideCaption}>{caption}</caption>
    <thead>
      <tr>
        {#each columns as c (c.key)}
          <th scope="col" class="a-{c.align ?? 'start'}" style:width={c.width}>{c.label}</th>
        {/each}
      </tr>
    </thead>
    <tbody>
      {#if loading && rows.length === 0}
        {#each [0, 1, 2, 3] as i (i)}
          <tr>
            {#each columns as c (c.key)}<td><Skeleton height={12} /></td>{/each}
          </tr>
        {/each}
      {:else}
        {#each rows as row (rowKey(row))}
          <tr>
            {#each columns as c (c.key)}
              <td class="a-{c.align ?? 'start'}" class:mono={c.mono}>
                {#if cell}{@render cell(row, c.key)}{:else}{String(row[c.key] ?? '')}{/if}
              </td>
            {/each}
          </tr>
        {/each}
      {/if}
    </tbody>
  </table>
  {#if !loading && rows.length === 0 && empty}<div class="empty">{@render empty()}</div>{/if}
</div>

<style>
  .wrap {
    width: 100%;
    overflow-x: auto;
  }
  table {
    width: 100%;
    min-width: 560px;
  }
  caption {
    padding-bottom: 8px;
    text-align: left;
    font-weight: var(--fw-semibold);
  }
  th {
    height: 40px;
    padding: 0 12px;
    border-bottom: 1px solid var(--line);
    color: var(--text-3);
    font-size: var(--fs-xs);
    font-weight: var(--fw-semibold);
    text-align: left;
    white-space: nowrap;
  }
  td {
    height: var(--row-h);
    padding: 6px 12px;
    border-bottom: 1px solid color-mix(in oklab, var(--line) 70%, transparent);
    vertical-align: middle;
  }
  tbody tr:hover td {
    background: var(--surface-2);
  }
  tbody tr:last-child td {
    border-bottom: 0;
  }
  .a-end {
    text-align: right;
  }
  .a-center {
    text-align: center;
  }
  .mono {
    font-family: var(--font-mono);
    font-size: 0.92em;
  }
</style>
