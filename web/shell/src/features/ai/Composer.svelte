<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  Composer · 对话输入框（Agent 页与悬浮窗共用）
  ───────────────────────────────────────────────────────────────
  - 支持视觉高亮可一键 × 删除的「交互文件引用」卡片（即使未配 AI 服务也能删除）
  - 支持传统模式文件上传：点击附件按钮选本机文件、拖拽文件进输入框、Ctrl+V 粘贴文件/截图
  - Enter 发送 · Shift+Enter 换行 · 输入法组字中不发送
-->
<script lang="ts" module>
  export interface ComposerCitation {
    path: string;
    name: string;
    isDir?: boolean;
  }
  export interface ComposerAttachment {
    path: string;
    name: string;
    size: number;
  }
</script>

<script lang="ts">
  import type { Snippet } from 'svelte';
  import { Icon, Spinner } from '$ui';
  import { agentExchange } from '$api/endpoints-agent';
  import { byteLength, MESSAGE_MAX_BYTES } from '$lib/ai/session-stream.svelte';
  import { reportError } from '$lib/errors';
  import { bytes as fmtBytes } from '$lib/format';
  import { toasts } from '$lib/toast.svelte';

  interface Props {
    value?: string;
    busy?: boolean;
    disabled?: boolean;
    disabledReason?: string;
    placeholder?: string;
    el?: HTMLTextAreaElement | null;
    citations?: readonly ComposerCitation[];
    onremovecitation?: (path: string) => void;
    onclearcitations?: () => void;
    /** 开启传统文件上传（选文件 / 拖拽 / Ctrl+V 粘贴） */
    allowUpload?: boolean;
    uploadDir?: string;
    onsend: (text: string) => Promise<unknown> | void;
    onstop?: () => void;
    tools?: Snippet;
  }
  let {
    value = $bindable(''),
    busy = false,
    disabled = false,
    disabledReason,
    placeholder = '想让 AI 帮你做什么？',
    el = $bindable(null),
    citations = [],
    onremovecitation,
    onclearcitations,
    allowUpload = false,
    uploadDir = '_chat_uploads',
    onsend,
    onstop,
    tools,
  }: Props = $props();

  const uid = $props.id();
  let sending = $state(false);
  let stopping = $state(false);
  let uploading = $state(false);
  let dragOver = $state(false);
  let attachments = $state<ComposerAttachment[]>([]);
  let fileInput = $state<HTMLInputElement>();

  function buildComposedText(): string {
    const headers: string[] = [];
    for (const c of citations) {
      headers.push(c.isDir ? `[交互目录: ${c.path}/]` : `[交互文件: ${c.path}]`);
    }
    for (const a of attachments) {
      headers.push(`[附件文件: ${a.path}]`);
    }
    const body = value.trim();
    if (!headers.length) return body;
    return body ? `${headers.join('\n')}\n\n${body}` : headers.join('\n');
  }

  const composedBytes = $derived(byteLength(buildComposedText()));
  const near = $derived(composedBytes > MESSAGE_MAX_BYTES * 0.8);
  const over = $derived(composedBytes > MESSAGE_MAX_BYTES);
  const hasPayload = $derived(value.trim().length > 0 || citations.length > 0 || attachments.length > 0);
  const canSend = $derived(!disabled && !sending && !busy && !uploading && !over && hasPayload);

  $effect(() => {
    void value;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 8 * 22 + 20) + 'px';
  });

  async function uploadFiles(files: File[]) {
    if (!allowUpload || uploading || !files.length) return;
    uploading = true;
    try {
      const res = await agentExchange.upload(uploadDir, files);
      const next = [...attachments];
      for (const f of res.items ?? []) {
        if (!next.some((x) => x.path === f.path)) {
          next.push({ path: f.path, name: f.name, size: f.size });
        }
      }
      attachments = next;
      toasts.success(`已附加 ${res.total} 个文件`);
    } catch (err) {
      reportError(err, '附件上传失败');
    } finally {
      uploading = false;
    }
  }

  function onFilePicked(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const files = input.files ? Array.from(input.files) : [];
    input.value = '';
    if (files.length) void uploadFiles(files);
  }

  function onPaste(e: ClipboardEvent) {
    if (!allowUpload || !e.clipboardData) return;
    const files: File[] = [];
    for (const item of Array.from(e.clipboardData.items ?? [])) {
      if (item.kind === 'file') {
        const f = item.getAsFile();
        if (f) files.push(f);
      }
    }
    if (files.length) {
      e.preventDefault();
      void uploadFiles(files);
    }
  }

  function onDrop(e: DragEvent) {
    dragOver = false;
    if (!allowUpload) return;
    const files = Array.from(e.dataTransfer?.files ?? []);
    if (!files.length) return;
    e.preventDefault();
    void uploadFiles(files);
  }

  function removeAttachment(path: string) {
    attachments = attachments.filter((a) => a.path !== path);
  }

  async function send() {
    if (!canSend) return;
    const text = buildComposedText();
    sending = true;
    try {
      await onsend(text);
      value = '';
      attachments = [];
      onclearcitations?.();
    } catch {
      /* 调用方已提示；保留文字与引用 */
    } finally {
      sending = false;
      el?.focus();
    }
  }

  async function stop() {
    if (!onstop || stopping) return;
    stopping = true;
    try {
      await onstop();
    } finally {
      stopping = false;
    }
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.key !== 'Enter' || e.shiftKey || e.isComposing || e.keyCode === 229) return;
    e.preventDefault();
    void send();
  }
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
  class="composer"
  class:disabled
  class:drag={dragOver}
  ondragover={(e) => {
    if (!allowUpload) return;
    e.preventDefault();
    dragOver = true;
  }}
  ondragleave={() => (dragOver = false)}
  ondrop={onDrop}
>
  {#if citations.length > 0 || attachments.length > 0}
    <div class="refs" aria-label="已引用与附加的文件">
      {#each citations as c (c.path)}
        <span class="cite-chip" title="交互文件夹引用：{c.path}">
          <span class="q-mark" aria-hidden="true">“</span>
          <span class="chip-name ellipsis">{c.name}</span>
          {#if c.path !== c.name}<span class="chip-path mono ellipsis">{c.path}</span>{/if}
          {#if onremovecitation}
            <button type="button" class="chip-x" aria-label="移除引用 {c.name}" onclick={() => onremovecitation(c.path)}>×</button>
          {/if}
        </span>
      {/each}
      {#each attachments as a (a.path)}
        <span class="att-chip" title="已上传附件：{a.path}">
          <Icon name="paperclip" size={12} />
          <span class="chip-name ellipsis">{a.name}</span>
          <span class="chip-path">{fmtBytes(a.size)}</span>
          <button type="button" class="chip-x" aria-label="移除附件 {a.name}" onclick={() => removeAttachment(a.path)}>×</button>
        </span>
      {/each}
    </div>
  {/if}

  <label class="sr-only" for="{uid}-in">给 AI 的消息</label>
  <textarea
    bind:this={el}
    bind:value
    id="{uid}-in"
    rows="1"
    placeholder={disabled ? (disabledReason ?? placeholder) : placeholder}
    {disabled}
    aria-describedby={near ? `${uid}-count` : undefined}
    {onkeydown}
    onpaste={onPaste}
  ></textarea>

  <div class="row">
    <div class="tools">
      {#if allowUpload}
        <button
          type="button"
          class="up-btn"
          title="上传本地文件（也可直接拖拽文件或 Ctrl+V 粘贴）"
          aria-label="上传附件"
          disabled={uploading}
          onclick={() => fileInput?.click()}
        >
          {#if uploading}<Spinner size={14} />{:else}<Icon name="paperclip" size={15} />{/if}
          <span>上传文件</span>
        </button>
        <input bind:this={fileInput} type="file" multiple hidden onchange={onFilePicked} />
      {/if}
      {@render tools?.()}
    </div>
    {#if near}
      <span id="{uid}-count" class="count" class:over aria-live="polite">
        {over ? '太长了，' : ''}{composedBytes.toLocaleString()} / {MESSAGE_MAX_BYTES.toLocaleString()} 字节
      </span>
    {/if}
    {#if busy && onstop}
      <button type="button" class="btn stop" onclick={stop} disabled={stopping} aria-label="停止">
        {#if stopping}<Spinner size={16} />{:else}<Icon name="stop" size={16} />{/if}
        <span>停止</span>
      </button>
    {:else}
      <button type="button" class="btn send" onclick={send} disabled={!canSend} aria-label="发送">
        {#if sending}<Spinner size={16} />{:else}<Icon name="send" size={18} />{/if}
      </button>
    {/if}
  </div>
</div>

<style>
  .composer {
    display: grid;
    gap: var(--s-2);
    padding: var(--s-3) var(--s-3) var(--s-2) var(--s-4);
    border-radius: var(--r-lg);
    background: var(--surface);
    border: 1px solid var(--line-input);
    transition: border-color var(--dur-1) var(--ease), background var(--dur-1) var(--ease);
  }
  .composer:focus-within {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-soft);
  }
  .composer.drag {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .disabled {
    background: var(--surface-2);
  }
  .refs {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .cite-chip,
  .att-chip {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    max-width: 100%;
    padding: 3px 6px 3px 9px;
    border-radius: var(--r-md);
    font-size: var(--fs-xs);
    line-height: 1.3;
  }
  .cite-chip {
    background: var(--info-soft);
    color: var(--info-text);
    border: 1px solid color-mix(in oklab, var(--info-text) 24%, transparent);
    border-left: 3px solid var(--info-text);
  }
  .att-chip {
    background: var(--accent-soft);
    color: var(--accent-text);
    border: 1px solid color-mix(in oklab, var(--accent) 26%, transparent);
  }
  .q-mark {
    font-size: 16px;
    font-weight: var(--fw-bold);
    line-height: 1;
  }
  .chip-name {
    font-weight: var(--fw-medium);
    max-width: 180px;
  }
  .chip-path {
    opacity: 0.72;
    font-size: var(--fs-2xs);
    max-width: 160px;
  }
  .chip-x {
    display: inline-grid;
    place-items: center;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    font-size: 14px;
    line-height: 1;
    color: inherit;
    opacity: 0.75;
  }
  .chip-x:hover {
    opacity: 1;
    background: color-mix(in oklab, currentColor 14%, transparent);
  }
  textarea {
    width: 100%;
    min-height: 26px;
    max-height: 196px;
    padding: 2px 0;
    border: 0;
    outline: 0;
    resize: none;
    background: none;
    color: var(--text);
    font: inherit;
    font-size: var(--fs-md);
    line-height: 22px;
  }
  textarea::placeholder {
    color: var(--text-3);
  }
  .row {
    display: flex;
    align-items: center;
    gap: var(--s-2);
    min-height: 36px;
  }
  .tools {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--s-1);
    flex: 1;
    min-width: 0;
  }
  .up-btn {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 30px;
    padding: 0 10px;
    border-radius: var(--r-pill);
    background: var(--surface-2);
    border: 1px solid var(--line);
    color: var(--text-2);
    font-size: var(--fs-xs);
    white-space: nowrap;
  }
  .up-btn:hover:not(:disabled) {
    background: var(--surface-3);
    color: var(--text);
    border-color: var(--line-strong);
  }
  .count {
    font-size: var(--fs-xs);
    color: var(--text-3);
    white-space: nowrap;
  }
  .count.over {
    color: var(--bad-text);
  }
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    height: 38px;
    min-width: 38px;
    border: 0;
    border-radius: var(--r-pill);
    font: inherit;
    font-size: var(--fs-sm);
    font-weight: var(--fw-medium);
    cursor: pointer;
    transition: transform var(--dur-1) var(--ease), opacity var(--dur-1) var(--ease);
  }
  .send {
    background: var(--ai-btn);
    color: #fff;
  }
  .send:disabled {
    background: var(--surface-3);
    color: var(--text-3);
    cursor: default;
  }
  .send:not(:disabled):active {
    transform: scale(0.94);
  }
  .stop {
    padding: 0 var(--s-4);
    background: var(--surface-3);
    color: var(--text);
  }
  .stop:hover {
    background: var(--line);
  }
</style>
