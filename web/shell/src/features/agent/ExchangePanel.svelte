<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  ExchangePanel · Agent 交互文件夹（用户 ↔ 服务器 Agent 双向文件交换区）
  ───────────────────────────────────────────────────────────────────────────────
  - 支持新建任意常用文件类型（.txt / .md / .json / .yaml / .conf / .sh / .py / .js / .ts / .html / .css / .env / .csv / .sql / .toml / 自定义）
  - 文件创建后支持一键直接打开「编辑内容」再次修改并保存，与「重命名」清晰分离
  - 点击「引用到对话」发出结构化引用，在输入框显示高亮可删除引用条
-->
<script lang="ts">
  import { untrack } from 'svelte';
  import {
    Alert,
    Button,
    ConfirmDialog,
    CopyButton,
    Dialog,
    Icon,
    IconButton,
    Input,
    Markdown,
    Menu,
    Skeleton,
  } from '$ui';
  import { agentExchange } from '$api/endpoints-agent';
  import type { AgentExchangeEntry, AgentExchangeListResult, AgentExchangePreview } from '$api/additions';
  import { describeError, reportError } from '$lib/errors';
  import { bytes as fmtBytes, relativeTime } from '$lib/format';
  import { session } from '$lib/session.svelte';
  import { toasts } from '$lib/toast.svelte';
  import type { ComposerCitation } from '../ai/Composer.svelte';

  interface Props {
    refreshTick?: number;
    oninsertref?: (ref: ComposerCitation) => void;
    onclose?: () => void;
  }
  let { refreshTick = 0, oninsertref, onclose }: Props = $props();

  const canWrite = $derived(session.can('host.agent_sessions:write'));

  const FILE_TYPES: readonly { ext: string; label: string; sample?: string }[] = [
    { ext: '.md', label: 'Markdown (.md)', sample: '# 标题\n\n' },
    { ext: '.txt', label: '纯文本 (.txt)' },
    { ext: '.json', label: 'JSON (.json)', sample: '{\n  \n}\n' },
    { ext: '.yaml', label: 'YAML (.yaml)' },
    { ext: '.conf', label: '配置 (.conf)' },
    { ext: '.sh', label: 'Shell (.sh)', sample: '#!/usr/bin/env bash\nset -euo pipefail\n\n' },
    { ext: '.py', label: 'Python (.py)' },
    { ext: '.js', label: 'JS (.js)' },
    { ext: '.ts', label: 'TS (.ts)' },
    { ext: '.html', label: 'HTML (.html)' },
    { ext: '.css', label: 'CSS (.css)' },
    { ext: '.env', label: 'ENV (.env)' },
    { ext: '.csv', label: 'CSV (.csv)' },
    { ext: '.sql', label: 'SQL (.sql)' },
    { ext: '.toml', label: 'TOML (.toml)' },
    { ext: '', label: '自定义扩展名' },
  ];

  let currentDir = $state('');
  let listing = $state<AgentExchangeListResult | null>(null);
  let loading = $state(true);
  let loadErr = $state('');
  let filter = $state('');

  /* 拖拽与上传 */
  let dragging = $state(false);
  let dragDepth = 0;
  let uploading = $state(false);
  let uploadPct = $state(0);
  let filePickerEl = $state<HTMLInputElement>();
  let dirPickerEl = $state<HTMLInputElement>();

  /* 新建子目录 */
  let mkdirOpen = $state(false);
  let mkdirName = $state('');
  let mkdirBusy = $state(false);
  let mkdirErr = $state('');

  /* 新建文件（多类型） */
  let newFileOpen = $state(false);
  let newFileExt = $state('.md');
  let newFileName = $state('');
  let newFileContent = $state('');
  let newFileBusy = $state(false);
  let newFileErr = $state('');

  /* 重命名 */
  let renameTarget = $state<AgentExchangeEntry | null>(null);
  let renameValue = $state('');
  let renameBusy = $state(false);
  let renameErr = $state('');

  /* 删除 */
  let deleteTarget = $state<AgentExchangeEntry | null>(null);
  let deleteOpen = $state(false);
  let deleteErr = $state('');

  /* 预览与在线编辑 */
  let previewOpen = $state(false);
  let previewLoading = $state(false);
  let previewData = $state<AgentExchangePreview | null>(null);
  let previewErr = $state('');
  let editMode = $state(false);
  let editDraft = $state('');
  let editSaving = $state(false);

  const crumbs = $derived.by(() => {
    const parts = currentDir ? currentDir.split('/').filter(Boolean) : [];
    const out: { label: string; path: string }[] = [{ label: '根目录', path: '' }];
    let acc = '';
    for (const part of parts) {
      acc = acc ? `${acc}/${part}` : part;
      out.push({ label: part, path: acc });
    }
    return out;
  });

  const filteredEntries = $derived.by(() => {
    const all = listing?.entries ?? [];
    const q = filter.trim().toLowerCase();
    if (!q) return all;
    return all.filter((e) => e.name.toLowerCase().includes(q));
  });

  async function loadDir(dir = currentDir, silent = false) {
    if (!silent) loading = true;
    loadErr = '';
    try {
      const res = await agentExchange.entries(dir);
      currentDir = res.path;
      listing = res;
    } catch (err) {
      loadErr = describeError(err).message;
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    void refreshTick;
    void loadDir(untrack(() => currentDir), Boolean(untrack(() => listing)));
  });

  function enterDir(dir: string) {
    filter = '';
    void loadDir(dir);
  }

  function triggerDownload(relPath: string) {
    const a = document.createElement('a');
    a.href = agentExchange.downloadUrl(relPath, false);
    a.download = '';
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  function insertRef(entry: Pick<AgentExchangeEntry, 'path' | 'name' | 'is_dir'>) {
    if (!oninsertref) return;
    oninsertref({ path: entry.path, name: entry.name, isDir: entry.is_dir });
    toasts.info(`已引用 ${entry.name}`);
  }

  /* ---------------------------------------------------------------- 上传 */
  async function uploadFiles(files: File[], relativePaths?: string[]) {
    if (!canWrite || !files.length || uploading) return;
    uploading = true;
    uploadPct = 0;
    try {
      const res = await agentExchange.upload(currentDir, files, relativePaths, (loaded, total) => {
        uploadPct = total > 0 ? Math.min(100, Math.round((loaded / total) * 100)) : 0;
      });
      toasts.success(`已上传 ${res.total} 个文件到${currentDir ? `「${currentDir}」` : '根目录'}`);
      await loadDir(currentDir, true);
    } catch (err) {
      reportError(err, '上传失败');
    } finally {
      uploading = false;
      uploadPct = 0;
    }
  }

  function onFileInput(e: Event, keepRel = false) {
    const input = e.currentTarget as HTMLInputElement;
    const list = input.files ? Array.from(input.files) : [];
    input.value = '';
    if (!list.length) return;
    const rels = keepRel
      ? list.map((f) => (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name)
      : undefined;
    void uploadFiles(list, rels);
  }

  type DropEntry = {
    isFile: boolean;
    isDirectory: boolean;
    name: string;
    file?: (cb: (f: File) => void, err?: (e: unknown) => void) => void;
    createReader?: () => { readEntries: (cb: (entries: DropEntry[]) => void, err?: (e: unknown) => void) => void };
  };

  async function collectDroppedEntries(entry: DropEntry, prefix = ''): Promise<{ file: File; rel: string }[]> {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isFile && entry.file) {
      const f = await new Promise<File>((resolve, reject) => entry.file!(resolve, reject));
      return [{ file: f, rel }];
    }
    if (entry.isDirectory && entry.createReader) {
      const reader = entry.createReader();
      const children: DropEntry[] = [];
      for (;;) {
        const batch = await new Promise<DropEntry[]>((resolve, reject) => reader.readEntries(resolve, reject));
        if (!batch.length) break;
        children.push(...batch);
      }
      const out: { file: File; rel: string }[] = [];
      for (const ch of children) {
        out.push(...(await collectDroppedEntries(ch, rel)));
      }
      return out;
    }
    return [];
  }

  async function onDrop(e: DragEvent) {
    e.preventDefault();
    dragDepth = 0;
    dragging = false;
    if (!canWrite || !e.dataTransfer) return;
    const items = Array.from(e.dataTransfer.items ?? []);
    const entries: DropEntry[] = [];
    for (const it of items) {
      const ent = (it as unknown as { webkitGetAsEntry?: () => DropEntry | null }).webkitGetAsEntry?.();
      if (ent) entries.push(ent);
    }
    if (entries.length > 0) {
      try {
        const collected: { file: File; rel: string }[] = [];
        for (const ent of entries) collected.push(...(await collectDroppedEntries(ent)));
        if (collected.length) {
          await uploadFiles(collected.map((x) => x.file), collected.map((x) => x.rel));
          return;
        }
      } catch {
        /* fallback */
      }
    }
    const files = Array.from(e.dataTransfer.files ?? []);
    if (files.length) void uploadFiles(files);
  }

  /* ---------------------------------------------------------------- 新建子文件夹 / 多类型文件 */
  function openMkdir() {
    mkdirName = '';
    mkdirErr = '';
    mkdirOpen = true;
  }

  async function submitMkdir(e?: SubmitEvent) {
    e?.preventDefault();
    const clean = mkdirName.trim().replace(/^\/+|\/+$/g, '');
    if (!clean || mkdirBusy) return;
    mkdirBusy = true;
    mkdirErr = '';
    try {
      const target = currentDir ? `${currentDir}/${clean}` : clean;
      const created = await agentExchange.mkdir(target);
      mkdirOpen = false;
      toasts.success(`已创建文件夹「${created.name}」`);
      await loadDir(currentDir, true);
    } catch (err) {
      mkdirErr = describeError(err).message;
    } finally {
      mkdirBusy = false;
    }
  }

  function openNewFile() {
    newFileExt = '.md';
    newFileName = '';
    newFileContent = '';
    newFileErr = '';
    newFileOpen = true;
  }

  function pickFileType(ext: string, sample?: string) {
    const prevSample = FILE_TYPES.find((t) => t.ext === newFileExt)?.sample ?? '';
    newFileExt = ext;
    if (ext && newFileName.trim()) {
      const base = newFileName.trim().replace(/\.[^./]+$/, '');
      if (base) newFileName = base + ext;
    }
    if (!newFileContent.trim() || newFileContent === prevSample) {
      newFileContent = sample ?? '';
    }
  }

  function resolvedNewFileName(): string {
    const clean = newFileName.trim().replace(/^\/+|\/+$/g, '');
    if (!clean) return '';
    if (!newFileExt) return clean;
    const leaf = clean.split('/').pop() ?? clean;
    if (leaf.includes('.')) return clean;
    return clean + newFileExt;
  }

  async function submitNewFile(e?: SubmitEvent) {
    e?.preventDefault();
    const clean = resolvedNewFileName();
    if (!clean || newFileBusy) return;
    newFileBusy = true;
    newFileErr = '';
    try {
      const target = currentDir ? `${currentDir}/${clean}` : clean;
      await agentExchange.writeFile(target, newFileContent);
      newFileOpen = false;
      toasts.success(`已创建文件「${clean}」`);
      await loadDir(currentDir, true);
    } catch (err) {
      newFileErr = describeError(err).message;
    } finally {
      newFileBusy = false;
    }
  }

  /* ---------------------------------------------------------------- 预览 / 直接编辑内容 */
  async function openPreview(entry: AgentExchangeEntry, startEditing = false) {
    if (entry.is_dir) {
      enterDir(entry.path);
      return;
    }
    previewOpen = true;
    previewLoading = true;
    previewData = null;
    previewErr = '';
    editMode = false;
    try {
      const res = await agentExchange.preview(entry.path);
      previewData = res;
      editDraft = res.content ?? '';
      if (startEditing && canWrite && res.is_text && !res.truncated) {
        editMode = true;
      } else if (startEditing && !res.is_text) {
        toasts.info('该文件为二进制格式，仅支持下载查看');
      }
    } catch (err) {
      previewErr = describeError(err).message;
    } finally {
      previewLoading = false;
    }
  }

  async function saveEdit() {
    if (!previewData || !canWrite || editSaving) return;
    editSaving = true;
    try {
      await agentExchange.writeFile(previewData.path, editDraft);
      previewData = { ...previewData, content: editDraft, truncated: false, size: new Blob([editDraft]).size };
      editMode = false;
      toasts.success(`已保存「${previewData.name}」`);
      await loadDir(currentDir, true);
    } catch (err) {
      reportError(err, '保存文件失败');
    } finally {
      editSaving = false;
    }
  }

  /* ---------------------------------------------------------------- 重命名 / 删除 */
  function openRename(entry: AgentExchangeEntry) {
    renameTarget = entry;
    renameValue = entry.name;
    renameErr = '';
  }

  async function submitRename(e?: SubmitEvent) {
    e?.preventDefault();
    const target = renameTarget;
    const nextName = renameValue.trim().replace(/^\/+|\/+$/g, '');
    if (!target || !nextName || renameBusy) return;
    const parent = target.path.includes('/') ? target.path.slice(0, target.path.lastIndexOf('/')) : '';
    const dst = parent ? `${parent}/${nextName}` : nextName;
    if (dst === target.path) {
      renameTarget = null;
      return;
    }
    renameBusy = true;
    renameErr = '';
    try {
      await agentExchange.rename(target.path, dst);
      renameTarget = null;
      toasts.success('已重命名');
      await loadDir(currentDir, true);
    } catch (err) {
      renameErr = describeError(err).message;
    } finally {
      renameBusy = false;
    }
  }

  function openDelete(entry: AgentExchangeEntry) {
    deleteTarget = entry;
    deleteErr = '';
    deleteOpen = true;
  }

  async function confirmDelete() {
    const target = deleteTarget;
    if (!target) return;
    deleteErr = '';
    try {
      await agentExchange.remove(target.path);
      toasts.success(`已删除「${target.name}」`);
      deleteTarget = null;
      await loadDir(currentDir, true);
    } catch (err) {
      deleteErr = describeError(err).message;
      throw err;
    }
  }

  const isMarkdown = (name: string) => /\.(md|markdown)$/i.test(name);
</script>

<section
  class="ex"
  class:dragging
  aria-label="Agent 交互文件夹"
  ondragenter={(e) => {
    e.preventDefault();
    dragDepth++;
    if (canWrite) dragging = true;
  }}
  ondragover={(e) => e.preventDefault()}
  ondragleave={(e) => {
    e.preventDefault();
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) dragging = false;
  }}
  ondrop={onDrop}
>
  <header class="ex-head">
    <div class="ex-ttl">
      <Icon name="folder" size={16} />
      <h3>交互文件夹</h3>
    </div>
    <div class="ex-head-ops">
      <IconButton icon="refresh" label="刷新文件列表" size="sm" variant="plain" onclick={() => void loadDir(currentDir)} />
      {#if onclose}
        <IconButton icon="x" label="收起交互文件夹" size="sm" variant="plain" onclick={onclose} />
      {/if}
    </div>
  </header>

  <p class="ex-desc">
    按子文件夹整理任务文件，支持创建/编辑常见文本与代码文件，点击引用图标将文件附入对话。
  </p>

  <div class="crumbs-bar">
    <nav class="crumbs" aria-label="文件夹路径">
      {#each crumbs as c, idx (c.path)}
        {#if idx > 0}<span class="sep">/</span>{/if}
        <button type="button" class="crumb" class:cur={idx === crumbs.length - 1} onclick={() => enterDir(c.path)}>
          {c.label}
        </button>
      {/each}
    </nav>
    <div class="crumb-ops">
      {#if listing?.root_hint}
        <CopyButton text={currentDir ? `${listing.root_hint}/${currentDir}` : listing.root_hint} label="复制服务器路径" />
      {/if}
      <IconButton
        icon="download"
        label={currentDir ? `打包下载 ${crumbs[crumbs.length - 1]?.label}.zip` : '打包下载整个交互文件夹 (.zip)'}
        size="sm"
        variant="plain"
        onclick={() => triggerDownload(currentDir)}
      />
    </div>
  </div>

  {#if canWrite}
    <div class="toolbar">
      <Button size="sm" variant="soft" icon="folder-plus" onclick={openMkdir}>新建目录</Button>
      <Button size="sm" variant="soft" icon="file" onclick={openNewFile}>新建文件</Button>
      <Button size="sm" variant="ghost" icon="upload" loading={uploading} onclick={() => filePickerEl?.click()}>上传</Button>
      <button type="button" class="mini-btn" title="选择本地整个文件夹上传到当前目录" onclick={() => dirPickerEl?.click()}>
        传文件夹
      </button>
      <input bind:this={filePickerEl} type="file" multiple hidden onchange={(e) => onFileInput(e, false)} />
      <input bind:this={dirPickerEl} type="file" webkitdirectory multiple hidden onchange={(e) => onFileInput(e, true)} />
    </div>
  {/if}

  {#if uploading}
    <div class="prog" role="status">
      <div class="prog-bar"><span style:width="{uploadPct}%"></span></div>
      <span>上传中 {uploadPct}%…</span>
    </div>
  {/if}

  {#if (listing?.entries.length ?? 0) > 4}
    <div class="search">
      <Icon name="search" size={13} />
      <input type="search" placeholder="筛选当前目录…" aria-label="筛选当前目录" bind:value={filter} />
    </div>
  {/if}

  <div class="body">
    {#if loading && !listing}
      <div class="pad"><Skeleton lines={5} height={36} /></div>
    {:else if loadErr}
      <div class="pad">
        <Alert>{loadErr}</Alert>
        <Button size="sm" variant="soft" onclick={() => void loadDir(currentDir)}>重试</Button>
      </div>
    {:else if !filteredEntries.length}
      <div class="empty">
        <Icon name="upload" size={26} />
        {#if filter.trim()}
          <p>当前目录下没有匹配“{filter}”的文件。</p>
        {:else}
          <p>当前目录为空</p>
          <span class="sub-hint">可拖拽本地文件或整个文件夹到此处，或点击上方「新建文件」/「新建目录」。</span>
        {/if}
      </div>
    {:else}
      <ul class="entries">
        {#if currentDir}
          <li>
            <button type="button" class="row up" onclick={() => enterDir(listing?.parent_path ?? '')}>
              <span class="ico dir"><Icon name="chevron-left" size={15} /></span>
              <span class="info"><span class="name">返回上级目录</span></span>
            </button>
          </li>
        {/if}
        {#each filteredEntries as ent (ent.path)}
          <li class="item">
            <button type="button" class="row" onclick={() => void openPreview(ent, false)}>
              <span class="ico" class:dir={ent.is_dir}>
                <Icon name={ent.is_dir ? 'folder' : 'file'} size={15} />
              </span>
              <span class="info">
                <span class="name" title={ent.name}>{ent.name}</span>
                <span class="sub">
                  {ent.is_dir ? `${ent.child_count ?? 0} 项` : fmtBytes(ent.size)} · {relativeTime(ent.updated_at)}
                </span>
              </span>
            </button>
            <div class="row-ops">
              {#if oninsertref}
                <IconButton icon="paperclip" size="sm" variant="plain" label="引用到对话" onclick={() => insertRef(ent)} />
              {/if}
              {#if canWrite && !ent.is_dir}
                <IconButton icon="edit" size="sm" variant="plain" label="编辑文件内容" onclick={() => void openPreview(ent, true)} />
              {/if}
              <IconButton
                icon="download"
                size="sm"
                variant="plain"
                label={ent.is_dir ? '打包下载 (.zip)' : '下载文件'}
                onclick={() => triggerDownload(ent.path)}
              />
              {#if canWrite}
                <Menu
                  label="更多文件操作"
                  align="end"
                  items={[
                    ...(!ent.is_dir ? [{ label: '编辑内容', icon: 'edit' as const, onselect: () => void openPreview(ent, true) }] : []),
                    { label: '重命名', icon: 'file' as const, onselect: () => openRename(ent) },
                    { label: '删除', icon: 'trash' as const, tone: 'danger' as const, onselect: () => openDelete(ent) },
                  ]}
                >
                  {#snippet trigger(props)}
                    <IconButton icon="more" size="sm" variant="plain" label="更多文件操作" {...props} />
                  {/snippet}
                </Menu>
              {/if}
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  </div>

  {#if listing}
    <footer class="foot">
      <span>{listing.total_dirs} 文件夹 · {listing.total_files} 文件</span>
      <span>{fmtBytes(listing.total_bytes)}</span>
    </footer>
  {/if}

  {#if dragging}
    <div class="drop-overlay" aria-hidden="true">
      <Icon name="upload" size={28} />
      <strong>松开即可上传</strong>
      <span>目标位置：/{currentDir || '根目录'}</span>
    </div>
  {/if}
</section>

<!-- 新建子文件夹 -->
<Dialog bind:open={mkdirOpen} title="新建子文件夹" size="sm">
  <form id="ex-mkdir" class="dlg-form" onsubmit={submitMkdir}>
    <Input
      label="文件夹名称（支持多级路径，如 审查报告/原始文件）"
      placeholder="例如：审查报告-20261125"
      required
      maxlength={160}
      bind:value={mkdirName}
    />
    {#if mkdirErr}<Alert>{mkdirErr}</Alert>{/if}
  </form>
  {#snippet footer()}
    <Button variant="plain" onclick={() => (mkdirOpen = false)}>取消</Button>
    <Button type="submit" form="ex-mkdir" variant="primary" loading={mkdirBusy} disabled={!mkdirName.trim()}>创建</Button>
  {/snippet}
</Dialog>

<!-- 新建常用类型文件 -->
<Dialog bind:open={newFileOpen} title="新建文件" size="md">
  <form id="ex-newfile" class="dlg-form" onsubmit={submitNewFile}>
    <div class="ft-bar" role="group" aria-label="快捷选择文件类型">
      {#each FILE_TYPES as ft (ft.label)}
        <button
          type="button"
          class="ft-pill"
          class:on={newFileExt === ft.ext}
          onclick={() => pickFileType(ft.ext, ft.sample)}
        >
          {ft.ext || '自定义'}
        </button>
      {/each}
    </div>
    <Input
      label="文件名（保存至 /{currentDir || '根目录'}，省略扩展名时自动补全 {newFileExt || '无'}）"
      placeholder={newFileExt ? `例如：notes${newFileExt}` : '例如：Dockerfile 或 config.ini'}
      required
      maxlength={160}
      bind:value={newFileName}
    />
    <textarea class="editor" rows="10" placeholder="输入文件内容（创建后也可随时打开重新编辑）…" bind:value={newFileContent}></textarea>
    {#if newFileErr}<Alert>{newFileErr}</Alert>{/if}
  </form>
  {#snippet footer()}
    <Button variant="plain" onclick={() => (newFileOpen = false)}>取消</Button>
    <Button type="submit" form="ex-newfile" variant="primary" loading={newFileBusy} disabled={!newFileName.trim()}>创建并保存</Button>
  {/snippet}
</Dialog>

<!-- 重命名 -->
<Dialog open={!!renameTarget} title="重命名" size="sm" onclose={() => (renameTarget = null)}>
  <form id="ex-rename" class="dlg-form" onsubmit={submitRename}>
    <Input label="新名称" required maxlength={160} bind:value={renameValue} />
    {#if renameErr}<Alert>{renameErr}</Alert>{/if}
  </form>
  {#snippet footer()}
    <Button variant="plain" onclick={() => (renameTarget = null)}>取消</Button>
    <Button type="submit" form="ex-rename" variant="primary" loading={renameBusy} disabled={!renameValue.trim()}>确认</Button>
  {/snippet}
</Dialog>

<!-- 删除确认 -->
<ConfirmDialog
  bind:open={deleteOpen}
  title="删除{deleteTarget?.is_dir ? '文件夹' : '文件'}「{deleteTarget?.name ?? ''}」？"
  tone="danger"
  confirmLabel="删除"
  errorText={deleteErr}
  onconfirm={confirmDelete}
>
  {deleteTarget?.is_dir ? '该文件夹及其中所有文件都会被永久删除，无法恢复。' : '删除后无法恢复。'}
</ConfirmDialog>

<!-- 文件预览与在线编辑 -->
<Dialog bind:open={previewOpen} title={previewData ? `${editMode ? '编辑：' : ''}${previewData.name}` : '文件预览'} size="lg">
  {#if previewLoading}
    <Skeleton lines={6} height={24} />
  {:else if previewErr}
    <Alert>{previewErr}</Alert>
  {:else if previewData}
    <div class="pv-meta">
      <span class="mono">{previewData.path}</span>
      <span>{fmtBytes(previewData.size)}</span>
      {#if previewData.truncated}<span class="trunc">仅展示前 512 KiB</span>{/if}
      <div class="pv-ops">
        {#if oninsertref}
          <Button
            size="sm"
            variant="soft"
            icon="paperclip"
            onclick={() => {
              insertRef({ path: previewData!.path, name: previewData!.name, is_dir: false });
              previewOpen = false;
            }}
          >
            引用到对话
          </Button>
        {/if}
        {#if previewData.is_text && canWrite && !previewData.truncated}
          <Button size="sm" variant={editMode ? 'soft' : 'ghost'} icon="edit" onclick={() => (editMode = !editMode)}>
            {editMode ? '切回预览' : '编辑内容'}
          </Button>
        {/if}
        <Button size="sm" variant="ghost" icon="download" onclick={() => triggerDownload(previewData!.path)}>下载</Button>
      </div>
    </div>

    {#if previewData.is_image}
      <div class="pv-img">
        <img src={agentExchange.downloadUrl(previewData.path, true)} alt={previewData.name} />
      </div>
    {:else if previewData.is_text}
      {#if editMode}
        <textarea class="editor big" rows="18" bind:value={editDraft}></textarea>
      {:else if isMarkdown(previewData.name)}
        <div class="pv-md"><Markdown source={previewData.content ?? ''} /></div>
      {:else}
        <pre class="pv-code">{previewData.content ?? ''}</pre>
      {/if}
    {:else}
      <div class="pv-bin">
        <Icon name="file" size={32} />
        <p>该文件为二进制格式（{previewData.mime_type || '未知类型'}），不支持直接在线编辑，请点击上方「下载」查看。</p>
      </div>
    {/if}
  {/if}
  {#snippet footer()}
    <Button variant="plain" onclick={() => (previewOpen = false)}>关闭</Button>
    {#if editMode && previewData?.is_text}
      <Button variant="primary" loading={editSaving} onclick={saveEdit}>保存修改</Button>
    {/if}
  {/snippet}
</Dialog>

<style>
  .ex {
    position: relative;
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    height: 100%;
    background: var(--surface);
  }
  .ex-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--s-2);
    padding: 10px var(--s-3);
    border-bottom: 1px solid var(--line);
    min-height: 52px;
  }
  .ex-ttl {
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }
  .ex-ttl h3 {
    margin: 0;
    font-size: var(--fs-md);
  }
  .ex-head-ops,
  .crumb-ops {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    flex: none;
  }
  .ex-desc {
    padding: 8px var(--s-3);
    font-size: var(--fs-xs);
    color: var(--text-3);
    line-height: 1.5;
    border-bottom: 1px solid var(--line);
    background: var(--surface-2);
  }
  .crumbs-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    padding: 6px var(--s-3);
    border-bottom: 1px solid var(--line);
  }
  .crumbs {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 2px;
    min-width: 0;
    font-size: var(--fs-xs);
  }
  .crumb {
    padding: 2px 5px;
    border-radius: var(--r-xs);
    color: var(--text-2);
    max-width: 140px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .crumb:hover {
    background: var(--surface-2);
    color: var(--text);
  }
  .crumb.cur {
    color: var(--text);
    font-weight: var(--fw-semibold);
  }
  .sep {
    color: var(--text-3);
  }
  .toolbar {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
    padding: 8px var(--s-3);
    border-bottom: 1px solid var(--line);
  }
  .mini-btn {
    padding: 4px 8px;
    border: 1px dashed var(--line-strong);
    border-radius: var(--r-sm);
    color: var(--text-2);
    font-size: var(--fs-xs);
  }
  .mini-btn:hover {
    background: var(--surface-2);
    color: var(--text);
  }
  .prog {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px var(--s-3);
    font-size: var(--fs-xs);
    color: var(--accent-text);
    background: var(--accent-soft);
  }
  .prog-bar {
    flex: 1;
    height: 4px;
    border-radius: var(--r-pill);
    background: color-mix(in oklab, var(--accent) 20%, transparent);
    overflow: hidden;
  }
  .prog-bar span {
    display: block;
    height: 100%;
    background: var(--accent);
    transition: width 120ms linear;
  }
  .search {
    display: flex;
    align-items: center;
    gap: 6px;
    margin: 8px var(--s-3) 0;
    padding: 0 10px;
    height: 30px;
    border: 1px solid var(--line);
    border-radius: var(--r-md);
    background: var(--surface-2);
    color: var(--text-3);
  }
  .search input {
    flex: 1;
    min-width: 0;
    border: 0;
    background: transparent;
    color: var(--text);
    font-size: var(--fs-xs);
  }
  .body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    overscroll-behavior: contain;
  }
  .pad {
    padding: var(--s-3);
    display: grid;
    gap: var(--s-2);
  }
  .empty {
    display: grid;
    justify-items: center;
    text-align: center;
    gap: 8px;
    padding: var(--s-6) var(--s-4);
    color: var(--text-3);
  }
  .empty p {
    font-size: var(--fs-sm);
    color: var(--text-2);
    font-weight: var(--fw-medium);
  }
  .sub-hint {
    font-size: var(--fs-xs);
    line-height: 1.5;
  }
  .entries {
    padding: 6px;
    display: grid;
    gap: 2px;
  }
  .item {
    display: flex;
    align-items: center;
    gap: 4px;
    border-radius: var(--r-md);
  }
  .item:hover {
    background: var(--surface-2);
  }
  .row {
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 7px 8px;
    border-radius: var(--r-md);
    text-align: left;
  }
  .row.up {
    width: 100%;
    color: var(--text-2);
  }
  .row.up:hover {
    background: var(--surface-2);
  }
  .ico {
    flex: none;
    display: grid;
    place-items: center;
    width: 28px;
    height: 28px;
    border-radius: var(--r-sm);
    background: var(--surface-2);
    color: var(--text-2);
  }
  .ico.dir {
    background: var(--accent-soft);
    color: var(--accent-text);
  }
  .info {
    display: grid;
    gap: 2px;
    min-width: 0;
    flex: 1;
  }
  .name {
    font-size: var(--fs-sm);
    font-weight: var(--fw-medium);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .sub {
    font-size: var(--fs-2xs);
    color: var(--text-3);
  }
  .row-ops {
    display: inline-flex;
    align-items: center;
    padding-right: 4px;
    opacity: 0.78;
  }
  .item:hover .row-ops,
  .item:focus-within .row-ops {
    opacity: 1;
  }
  .foot {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 7px var(--s-3);
    border-top: 1px solid var(--line);
    background: var(--surface-2);
    font-size: var(--fs-2xs);
    color: var(--text-3);
  }
  .drop-overlay {
    position: absolute;
    inset: 8px;
    z-index: 10;
    display: grid;
    place-content: center;
    justify-items: center;
    gap: 6px;
    border-radius: var(--r-lg);
    border: 2px dashed var(--accent);
    background: color-mix(in oklab, var(--accent-soft) 92%, var(--surface));
    color: var(--accent-text);
    pointer-events: none;
  }
  .dlg-form {
    display: grid;
    gap: var(--s-3);
  }
  .ft-bar {
    display: flex;
    flex-wrap: wrap;
    gap: 5px;
  }
  .ft-pill {
    padding: 3px 9px;
    border-radius: var(--r-pill);
    border: 1px solid var(--line);
    background: var(--surface-2);
    color: var(--text-2);
    font-family: var(--font-mono);
    font-size: var(--fs-2xs);
  }
  .ft-pill:hover {
    border-color: var(--line-strong);
    color: var(--text);
  }
  .ft-pill.on {
    border-color: var(--accent);
    background: var(--accent-soft);
    color: var(--accent-text);
    font-weight: var(--fw-semibold);
  }
  .editor {
    width: 100%;
    padding: 10px 12px;
    border-radius: var(--r-md);
    border: 1px solid var(--line);
    background: var(--surface-2);
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    line-height: 1.55;
    resize: vertical;
  }
  .editor.big {
    min-height: 360px;
  }
  .pv-meta {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: var(--s-3);
    font-size: var(--fs-xs);
    color: var(--text-3);
  }
  .pv-ops {
    margin-left: auto;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .trunc {
    padding: 1px 6px;
    border-radius: var(--r-pill);
    background: var(--warn-soft);
    color: var(--warn-text);
  }
  .pv-md,
  .pv-code {
    max-height: 60vh;
    overflow: auto;
    padding: var(--s-3);
    border-radius: var(--r-md);
    border: 1px solid var(--line);
  }
  .pv-md {
    background: var(--surface-2);
  }
  .pv-code {
    background: var(--surface-sunk);
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    line-height: 1.55;
    white-space: pre-wrap;
    word-break: break-word;
  }
  .pv-img {
    display: grid;
    place-items: center;
    max-height: 60vh;
    overflow: auto;
    padding: var(--s-3);
    border-radius: var(--r-md);
    background: var(--surface-2);
  }
  .pv-img img {
    max-width: 100%;
    max-height: 54vh;
    border-radius: var(--r-sm);
  }
  .pv-bin {
    display: grid;
    justify-items: center;
    text-align: center;
    gap: 10px;
    padding: var(--s-6);
    color: var(--text-2);
  }
</style>
