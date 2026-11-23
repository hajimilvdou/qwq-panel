<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!--
  AgentWorkspaceModal · Agent 三大目录（提示词 / Skills / MCP）与官方仓库管理
  ───────────────────────────────────────────────────────────────────────────────
  - 自定义提示词严格按各家核心分开：CLAUDE.md / codex AGENTS.md / opencode AGENTS.md / native SYSTEM.md
  - Skills 技能目录与 MCP 服务目录独立管理，均支持网页拖拽上传文件与在线编辑
  - 内置官方仓库（Anthropic Skills / OpenAI Codex Skills / MCP Official Servers）搜索与一键下载安装
-->
<script lang="ts">
  import { Alert, Button, Chip, Dialog, EmptyState, Icon, Input, Skeleton, Switch } from '$ui';
  import { safeExternalHref } from '$ui/safe-url';
  import { agent } from '$api/endpoints';
  import type {
    AgentCorePromptTarget,
    AgentMCPServerEntry,
    AgentRegistryItem,
    AgentRegistrySourceMeta,
    AgentWorkspaceFileEntry,
    WorkspaceArea,
  } from '$api/additions';
  import { describeError, reportError } from '$lib/errors';
  import { toasts } from '$lib/toast.svelte';

  interface Props {
    open: boolean;
    initialTab?: 'prompts' | 'skills' | 'mcp' | 'registry';
  }
  let { open = $bindable(false), initialTab = 'prompts' }: Props = $props();

  type TabKey = 'prompts' | 'skills' | 'mcp' | 'registry';
  let tab = $state<TabKey>('prompts');

  /* ── 目录与文件状态 ───────────────────────────────────────── */
  let loading = $state(false);
  let errMsg = $state('');
  let dirHint = $state('');
  let files = $state<AgentWorkspaceFileEntry[]>([]);
  let promptTargets = $state<AgentCorePromptTarget[]>([]);
  let activePromptPath = $state('claude-code/CLAUDE.md');
  let selectedPath = $state('');
  let editorText = $state('');
  let editorDirty = $state(false);
  let saving = $state(false);

  /* Skills 新建 */
  let newSkillName = $state('');

  /* MCP 可视化列表 */
  let mcpServers = $state<AgentMCPServerEntry[]>([]);
  let mcpRawMode = $state(false);
  let newMcpOpen = $state(false);
  let newMcp = $state({ id: '', name: '', transport: 'stdio' as 'stdio' | 'http', command: 'npx', args: '-y ', url: '' });

  /* 拖拽上传 */
  let dragOver = $state(false);
  let uploading = $state(false);
  let fileInputEl = $state<HTMLInputElement | null>(null);

  /* 官方仓库 */
  let regLoading = $state(false);
  let regRefreshing = $state(false);
  let regSources = $state<AgentRegistrySourceMeta[]>([]);
  let regItems = $state<AgentRegistryItem[]>([]);
  let regKind = $state<'all' | 'skill' | 'mcp'>('all');
  let regSource = $state('all');
  let regQuery = $state('');
  let installing = $state<Record<string, boolean>>({});

  $effect(() => {
    if (open) {
      tab = initialTab;
      void loadTab(initialTab);
    }
  });

  async function switchTab(next: TabKey) {
    tab = next;
    await loadTab(next);
  }

  async function loadTab(t: TabKey) {
    errMsg = '';
    if (t === 'registry') {
      await loadRegistry(false);
      return;
    }
    loading = true;
    try {
      const res = await agent.workspaceList(t);
      dirHint = res.directory_hint;
      files = res.items;
      if (t === 'prompts') {
        promptTargets = res.prompt_targets ?? [];
        const targetPath = promptTargets.some((x) => x.rel_path === activePromptPath)
          ? activePromptPath
          : (promptTargets[0]?.rel_path ?? 'claude-code/CLAUDE.md');
        activePromptPath = targetPath;
        await openFile('prompts', targetPath);
      } else if (t === 'mcp') {
        await openFile('mcp', 'servers.json');
        parseMcpFromEditor();
      } else if (t === 'skills') {
        if (selectedPath && files.some((f) => f.path === selectedPath)) {
          await openFile('skills', selectedPath);
        } else if (files.length > 0) {
          await openFile('skills', files[0]!.path);
        } else {
          selectedPath = '';
          editorText = '';
          editorDirty = false;
        }
      }
    } catch (err) {
      errMsg = describeError(err).message;
    } finally {
      loading = false;
    }
  }

  async function openFile(area: WorkspaceArea, path: string) {
    selectedPath = path;
    editorDirty = false;
    try {
      const f = await agent.workspaceRead(area, path);
      editorText = f.content;
    } catch (err) {
      editorText = '';
      errMsg = describeError(err).message;
    }
  }

  async function saveCurrentFile() {
    if (tab === 'registry' || !selectedPath || saving) return;
    saving = true;
    errMsg = '';
    try {
      await agent.workspaceWrite({ area: tab, path: selectedPath, content: editorText });
      editorDirty = false;
      toasts.success(`已保存 ${selectedPath}`);
      if (tab === 'mcp' && selectedPath === 'servers.json') parseMcpFromEditor();
      const res = await agent.workspaceList(tab);
      files = res.items;
    } catch (err) {
      errMsg = describeError(err).message;
    } finally {
      saving = false;
    }
  }

  async function deletePath(area: WorkspaceArea, path: string) {
    try {
      await agent.workspaceDelete(area, path);
      toasts.success(`已删除 ${path}`);
      if (selectedPath === path) {
        selectedPath = '';
        editorText = '';
      }
      await loadTab(area);
    } catch (err) {
      reportError(err, '删除失败');
    }
  }

  /* ── Skills 新建 ─────────────────────────────────────────── */
  async function createSkill() {
    const slug = newSkillName
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, '-')
      .replace(/^-+|-+$/g, '');
    if (!slug) return;
    const p = `${slug}/SKILL.md`;
    const tpl = `---\nname: ${slug}\ndescription: 自定义运维技能\n---\n\n# ${slug}\n\n在此编写触发条件与操作步骤…\n`;
    try {
      await agent.workspaceWrite({ area: 'skills', path: p, content: tpl });
      newSkillName = '';
      toasts.success(`已新建技能 ${slug}`);
      await loadTab('skills');
      await openFile('skills', p);
    } catch (err) {
      reportError(err, '创建技能失败');
    }
  }

  /* ── MCP 管理 ────────────────────────────────────────────── */
  function parseMcpFromEditor() {
    try {
      const parsed = JSON.parse(editorText || '{"servers":[]}') as { servers?: AgentMCPServerEntry[] };
      mcpServers = Array.isArray(parsed.servers) ? parsed.servers : [];
    } catch {
      mcpServers = [];
    }
  }

  async function persistMcpServers(next: AgentMCPServerEntry[]) {
    const text = JSON.stringify({ servers: next }, null, 2) + '\n';
    saving = true;
    try {
      await agent.workspaceWrite({ area: 'mcp', path: 'servers.json', content: text });
      mcpServers = next;
      editorText = text;
      editorDirty = false;
      toasts.success('已更新 MCP 服务配置');
    } catch (err) {
      reportError(err, '保存 MCP 配置失败');
    } finally {
      saving = false;
    }
  }

  function toggleMcp(id: string, enabled: boolean) {
    void persistMcpServers(mcpServers.map((s) => (s.id === id ? { ...s, enabled } : s)));
  }

  function removeMcp(id: string) {
    void persistMcpServers(mcpServers.filter((s) => s.id !== id));
  }

  async function addCustomMcp() {
    const id = newMcp.id
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, '-');
    if (!id) return;
    const entry: AgentMCPServerEntry = {
      id,
      name: newMcp.name.trim() || id,
      transport: newMcp.transport,
      enabled: true,
      ...(newMcp.transport === 'http'
        ? { url: newMcp.url.trim() }
        : { command: newMcp.command.trim(), args: newMcp.args.trim().split(/\s+/).filter(Boolean) }),
    };
    const next = [...mcpServers.filter((s) => s.id !== id), entry];
    await persistMcpServers(next);
    newMcpOpen = false;
    newMcp = { id: '', name: '', transport: 'stdio', command: 'npx', args: '-y ', url: '' };
  }

  /* ── 拖拽上传（Prompts / Skills / MCP 全部支持）───────────── */
  function readFileAsBase64(file: File): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const res = String(reader.result ?? '');
        const idx = res.indexOf(',');
        resolve(idx >= 0 ? res.slice(idx + 1) : res);
      };
      reader.onerror = () => reject(reader.error ?? new Error('读取文件失败'));
      reader.readAsDataURL(file);
    });
  }

  async function handleDroppedFiles(fileList: FileList | null) {
    if (!fileList || fileList.length === 0 || tab === 'registry') return;
    uploading = true;
    errMsg = '';
    let okCount = 0;
    try {
      for (const file of Array.from(fileList)) {
        if (file.size > 2 * 1024 * 1024) {
          toasts.error(`${file.name} 超过 2 MiB 上限，已跳过`);
          continue;
        }
        let targetPath = file.name;
        if (tab === 'prompts') {
          targetPath = activePromptPath;
        } else if (tab === 'skills') {
          const rel = (file as File & { webkitRelativePath?: string }).webkitRelativePath;
          if (rel && rel.includes('/')) {
            targetPath = rel.replace(/^\/+/, '');
          } else if (file.name.toLowerCase() === 'skill.md') {
            targetPath = `uploaded-${Date.now()}/SKILL.md`;
          } else if (file.name.toLowerCase().endsWith('.md')) {
            const slug = file.name
              .replace(/\.md$/i, '')
              .toLowerCase()
              .replace(/[^a-z0-9_-]+/g, '-');
            targetPath = `${slug || 'custom-skill'}/SKILL.md`;
          } else {
            const grp = selectedPath.includes('/') ? selectedPath.split('/')[0]! : 'custom-assets';
            targetPath = `${grp}/${file.name}`;
          }
        } else if (tab === 'mcp') {
          targetPath = file.name.toLowerCase().endsWith('.json') ? 'servers.json' : file.name;
        }
        const b64 = await readFileAsBase64(file);
        await agent.workspaceWrite({ area: tab, path: targetPath, content_base64: b64 });
        okCount++;
        selectedPath = targetPath;
      }
      if (okCount > 0) {
        toasts.success(`已上传 ${okCount} 个文件到 ${tab === 'prompts' ? activePromptPath : tab + '/'}`);
        await loadTab(tab);
      }
    } catch (err) {
      errMsg = describeError(err).message;
    } finally {
      uploading = false;
      dragOver = false;
      if (fileInputEl) fileInputEl.value = '';
    }
  }

  /* ── 官方仓库检索与下载安装 ───────────────────────────────── */
  async function loadRegistry(refresh: boolean) {
    if (refresh) regRefreshing = true;
    else regLoading = true;
    errMsg = '';
    try {
      const res = await agent.registrySearch({
        kind: regKind,
        source: regSource,
        q: regQuery.trim() || undefined,
        refresh,
      });
      regSources = res.sources;
      regItems = res.items;
      if (refresh) {
        toasts.success(res.live_refreshed ? '已从 GitHub 官方仓库同步最新清单' : '当前使用内置精选清单（未能直连 GitHub）');
      }
    } catch (err) {
      errMsg = describeError(err).message;
    } finally {
      regLoading = false;
      regRefreshing = false;
    }
  }

  async function installFromRegistry(item: AgentRegistryItem) {
    if (installing[item.id]) return;
    installing[item.id] = true;
    try {
      const res = await agent.registryInstall(item.id);
      toasts.success(res.message);
      regItems = regItems.map((x) => (x.id === item.id ? { ...x, installed: true } : x));
    } catch (err) {
      reportError(err, '安装失败');
    } finally {
      installing[item.id] = false;
    }
  }

  const activePromptMeta = $derived(promptTargets.find((t) => t.rel_path === activePromptPath));
  const skillGroups = $derived.by(() => {
    const map = new Map<string, AgentWorkspaceFileEntry[]>();
    for (const f of files) {
      const g = f.group || '根目录';
      const arr = map.get(g) ?? [];
      arr.push(f);
      map.set(g, arr);
    }
    return Array.from(map.entries());
  });
</script>

<Dialog bind:open title="Agent 资源与官方仓库管理" description="提示词（按核心隔离）、Skills 技能与 MCP 服务分目录管理，支持网页拖拽上传与官方仓库一键下载。" size="lg">
  <div class="ws">
    <div class="tabs" role="tablist" aria-label="Agent 资源分区">
      <button type="button" role="tab" aria-selected={tab === 'prompts'} class:on={tab === 'prompts'} onclick={() => void switchTab('prompts')}>
        各家自定义提示词
      </button>
      <button type="button" role="tab" aria-selected={tab === 'skills'} class:on={tab === 'skills'} onclick={() => void switchTab('skills')}>
        Skills 技能目录
      </button>
      <button type="button" role="tab" aria-selected={tab === 'mcp'} class:on={tab === 'mcp'} onclick={() => void switchTab('mcp')}>
        MCP 服务目录
      </button>
      <button type="button" role="tab" aria-selected={tab === 'registry'} class:on={tab === 'registry'} onclick={() => void switchTab('registry')}>
        官方仓库市场
      </button>
    </div>

    {#if errMsg}<Alert>{errMsg}</Alert>{/if}

    {#if tab !== 'registry'}
      <!-- 通用拖拽上传区 -->
      <div
        class="dropzone"
        class:over={dragOver}
        role="region"
        aria-label="拖拽上传文件"
        ondragover={(e) => {
          e.preventDefault();
          dragOver = true;
        }}
        ondragleave={() => (dragOver = false)}
        ondrop={(e) => {
          e.preventDefault();
          void handleDroppedFiles(e.dataTransfer?.files ?? null);
        }}
      >
        <input
          bind:this={fileInputEl}
          type="file"
          multiple={tab === 'skills'}
          hidden
          onchange={(e) => void handleDroppedFiles((e.currentTarget as HTMLInputElement).files)}
        />
        <span class="dz-text">
          {#if uploading}
            正在上传并保存…
          {:else if tab === 'prompts'}
            将 <code>.md</code> 提示词文件拖拽到此处，自动写入 <code>{activePromptPath}</code>
          {:else if tab === 'skills'}
            将 <code>SKILL.md</code>、技能脚本或文件夹拖拽到此处上传到 <code>skills/</code>（支持多文件，单文件 ≤ 2 MiB）
          {:else}
            将 <code>servers.json</code> 等 MCP 配置文件拖拽到此处导入 <code>mcp/</code>
          {/if}
        </span>
        <Button size="sm" variant="soft" loading={uploading} onclick={() => fileInputEl?.click()}>选择文件上传</Button>
      </div>
    {/if}

    {#if tab === 'prompts'}
      <div class="subtabs">
        {#each promptTargets as pt (pt.rel_path)}
          <button
            type="button"
            class="pill"
            class:on={activePromptPath === pt.rel_path}
            onclick={() => {
              activePromptPath = pt.rel_path;
              void openFile('prompts', pt.rel_path);
            }}
          >
            <strong>{pt.display_name}</strong>
            <code>{pt.file_name}</code>
          </button>
        {/each}
      </div>
      {#if activePromptMeta}
        <p class="small muted hint-row">
          <span>{activePromptMeta.description}</span>
          <code class="dir-tag">{dirHint}/{activePromptMeta.rel_path}</code>
        </p>
      {/if}
      {#if loading}
        <Skeleton lines={4} height={42} />
      {:else}
        <textarea
          class="code-area"
          rows="12"
          placeholder="在此输入该核心专属的系统/全局提示词（支持 Markdown），或将本地 .md 文件直接拖入上方上传区…"
          bind:value={editorText}
          oninput={() => (editorDirty = true)}
        ></textarea>
        <div class="bar-end">
          <Button size="sm" variant="primary" loading={saving} disabled={!editorDirty} onclick={() => void saveCurrentFile()}>
            保存 {activePromptMeta?.file_name ?? '提示词'}
          </Button>
        </div>
      {/if}
    {:else if tab === 'skills'}
      <div class="split">
        <div class="tree">
          <div class="tree-head">
            <input class="mini-in" placeholder="新技能名称（如 nginx-ops）" bind:value={newSkillName} />
            <Button size="sm" variant="soft" disabled={!newSkillName.trim()} onclick={() => void createSkill()}>新建</Button>
          </div>
          {#if loading}
            <Skeleton lines={4} height={32} />
          {:else if skillGroups.length === 0}
            <EmptyState compact title="技能目录为空" description="可拖拽上传 SKILL.md，或切换到「官方仓库市场」一键下载。" />
          {:else}
            <div class="tree-list">
              {#each skillGroups as [grp, list] (grp)}
                <div class="grp">
                  <div class="grp-h">
                    <span class="mono">{grp}/</span>
                    {#if grp !== '根目录'}
                      <button type="button" class="del-link" onclick={() => void deletePath('skills', grp)}>删整组</button>
                    {/if}
                  </div>
                  {#each list as f (f.path)}
                    <div class="f-row" class:on={selectedPath === f.path}>
                      <button type="button" class="f-btn" onclick={() => void openFile('skills', f.path)}>{f.name}</button>
                      <button type="button" class="del-x" title="删除文件" onclick={() => void deletePath('skills', f.path)}>×</button>
                    </div>
                  {/each}
                </div>
              {/each}
            </div>
          {/if}
        </div>
        <div class="editor-col">
          {#if selectedPath}
            <div class="ed-head">
              <code class="mono">skills/{selectedPath}</code>
              <Button size="sm" variant="primary" loading={saving} disabled={!editorDirty} onclick={() => void saveCurrentFile()}>保存</Button>
            </div>
            <textarea class="code-area" rows="12" bind:value={editorText} oninput={() => (editorDirty = true)}></textarea>
          {:else}
            <EmptyState compact title="选择左侧技能文件查看或编辑" description="也可直接拖拽 .md 文件到上方上传区自动建组。" />
          {/if}
        </div>
      </div>
    {:else if tab === 'mcp'}
      <div class="ed-head">
        <span class="small muted">目录：<code class="mono">{dirHint}/servers.json</code>（已启用的 MCP 将自动挂载给 Claude Code / Codex）</span>
        <div class="row-actions">
          <Button size="sm" variant="soft" onclick={() => (newMcpOpen = !newMcpOpen)}>添加自定义 MCP</Button>
          <Button size="sm" variant="plain" onclick={() => (mcpRawMode = !mcpRawMode)}>
            {mcpRawMode ? '切回卡片视图' : '编辑原始 JSON'}
          </Button>
        </div>
      </div>

      {#if newMcpOpen}
        <div class="mcp-form">
          <div class="grid-2">
            <Input label="服务 ID" placeholder="如 my-db" mono bind:value={newMcp.id} />
            <Input label="显示名称" placeholder="如 内部数据库 MCP" bind:value={newMcp.name} />
          </div>
          <div class="subtabs">
            <button type="button" class="pill" class:on={newMcp.transport === 'stdio'} onclick={() => (newMcp.transport = 'stdio')}>本地命令行 (stdio)</button>
            <button type="button" class="pill" class:on={newMcp.transport === 'http'} onclick={() => (newMcp.transport = 'http')}>远程 HTTP / SSE</button>
          </div>
          {#if newMcp.transport === 'stdio'}
            <div class="grid-2">
              <Input label="执行命令" mono bind:value={newMcp.command} />
              <Input label="参数（空格分隔）" mono bind:value={newMcp.args} />
            </div>
          {:else}
            <Input label="MCP HTTP 地址" mono placeholder="https://mcp.example.com/sse" bind:value={newMcp.url} />
          {/if}
          <div class="bar-end">
            <Button size="sm" variant="plain" onclick={() => (newMcpOpen = false)}>取消</Button>
            <Button size="sm" variant="primary" disabled={!newMcp.id.trim()} onclick={() => void addCustomMcp()}>添加到 MCP 目录</Button>
          </div>
        </div>
      {/if}

      {#if mcpRawMode}
        <textarea class="code-area" rows="12" bind:value={editorText} oninput={() => (editorDirty = true)}></textarea>
        <div class="bar-end">
          <Button size="sm" variant="primary" loading={saving} disabled={!editorDirty} onclick={() => void saveCurrentFile()}>保存 servers.json</Button>
        </div>
      {:else if mcpServers.length === 0}
        <EmptyState compact title="还没有自定义 MCP 服务" description="宿主内置 MCP 桥已自动生效；如需更多工具，可去「官方仓库市场」一键安装 Fetch / Git / Playwright / Context7。">
          {#snippet action()}
            <Button size="sm" variant="soft" onclick={() => void switchTab('registry')}>去官方仓库挑选</Button>
          {/snippet}
        </EmptyState>
      {:else}
        <ul class="mcp-list">
          {#each mcpServers as m (m.id)}
            <li>
              <div class="mcp-info">
                <div class="mcp-title">
                  <strong>{m.name}</strong>
                  <Chip size="sm" tone="neutral">{m.transport}</Chip>
                  {#if m.source}<span class="small muted">{m.source}</span>{/if}
                </div>
                {#if m.description}<p class="small muted">{m.description}</p>{/if}
                <code class="small mono">
                  {m.transport === 'http' ? m.url : [m.command, ...(m.args ?? [])].join(' ')}
                </code>
              </div>
              <div class="row-actions">
                <Switch label="启用" checked={m.enabled} onchange={(v) => toggleMcp(m.id, v)} />
                <Button size="sm" variant="plain" onclick={() => removeMcp(m.id)}>移除</Button>
              </div>
            </li>
          {/each}
        </ul>
      {/if}
    {:else}
      <!-- 官方仓库市场 -->
      <div class="reg-bar">
        <input
          class="reg-search"
          type="search"
          placeholder="搜索官方 Skills 或 MCP（如 playwright、fetch、security、pdf、context7…）"
          bind:value={regQuery}
          onkeydown={(e) => e.key === 'Enter' && void loadRegistry(false)}
        />
        <Button size="sm" variant="soft" onclick={() => void loadRegistry(false)}>查找</Button>
        <Button size="sm" variant="plain" loading={regRefreshing} onclick={() => void loadRegistry(true)}>同步线上仓库</Button>
      </div>

      <div class="subtabs">
        <button type="button" class="pill" class:on={regKind === 'all'} onclick={() => { regKind = 'all'; void loadRegistry(false); }}>全部</button>
        <button type="button" class="pill" class:on={regKind === 'skill'} onclick={() => { regKind = 'skill'; void loadRegistry(false); }}>官方 Skills</button>
        <button type="button" class="pill" class:on={regKind === 'mcp'} onclick={() => { regKind = 'mcp'; void loadRegistry(false); }}>官方 MCP</button>
        {#each regSources as src (src.id)}
          <button
            type="button"
            class="pill"
            class:on={regSource === src.id}
            onclick={() => {
              regSource = regSource === src.id ? 'all' : src.id;
              void loadRegistry(false);
            }}
          >
            {src.repo}
          </button>
        {/each}
      </div>

      {#if regLoading}
        <Skeleton lines={5} height={52} />
      {:else if regItems.length === 0}
        <EmptyState compact title="未找到匹配项" description="换个关键词，或点击「同步线上仓库」拉取最新官方列表。" />
      {:else}
        <ul class="reg-list">
          {#each regItems as item (item.id)}
            <li>
              <div class="mcp-info">
                <div class="mcp-title">
                  <strong>{item.name}</strong>
                  <Chip size="sm" tone={item.kind === 'mcp' ? 'accent' : 'ok'}>{item.kind === 'mcp' ? 'MCP' : 'Skill'}</Chip>
                  <span class="small muted mono">{item.repo}</span>
                </div>
                <p class="small muted">{item.description}</p>
              </div>
              <div class="row-actions">
                {#if safeExternalHref(item.repo_url)}
                  <a class="repo-link" href={safeExternalHref(item.repo_url)} target="_blank" rel="noopener noreferrer">源码</a>
                {/if}
                <Button
                  size="sm"
                  variant={item.installed ? 'soft' : 'primary'}
                  loading={installing[item.id]}
                  onclick={() => void installFromRegistry(item)}
                >
                  {item.installed ? '已安装 · 更新' : '下载使用'}
                </Button>
              </div>
            </li>
          {/each}
        </ul>
      {/if}
    {/if}
  </div>

  {#snippet footer()}
    <Button variant="plain" onclick={() => (open = false)}>关闭</Button>
  {/snippet}
</Dialog>

<style>
  .ws {
    display: grid;
    gap: var(--s-3);
  }
  .tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    border-bottom: 1px solid var(--line);
    padding-bottom: var(--s-2);
  }
  .tabs button {
    padding: 6px 12px;
    border-radius: var(--r-pill);
    border: 1px solid transparent;
    background: transparent;
    color: var(--text-2);
    font: inherit;
    font-size: var(--fs-sm);
    cursor: pointer;
  }
  .tabs button:hover {
    background: var(--surface-2);
    color: var(--text);
  }
  .tabs button.on {
    background: var(--accent-soft);
    color: var(--accent-text);
    border-color: color-mix(in oklab, var(--accent) 30%, transparent);
    font-weight: var(--fw-medium);
  }
  .dropzone {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--s-3);
    padding: 10px 14px;
    border-radius: var(--r-md);
    border: 1.5px dashed var(--line-strong);
    background: var(--surface-2);
    transition: border-color var(--dur-1) var(--ease), background var(--dur-1) var(--ease);
  }
  .dropzone.over {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  .dz-text {
    font-size: var(--fs-xs);
    color: var(--text-2);
  }
  .subtabs {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 10px;
    border-radius: var(--r-pill);
    border: 1px solid var(--line);
    background: var(--surface);
    color: var(--text-2);
    font: inherit;
    font-size: var(--fs-xs);
    cursor: pointer;
  }
  .pill.on {
    border-color: var(--accent);
    background: var(--accent-soft);
    color: var(--accent-text);
  }
  .hint-row {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    gap: 8px;
    margin: 0;
  }
  .dir-tag {
    font-size: 11px;
    opacity: 0.8;
  }
  .code-area {
    width: 100%;
    padding: 10px 12px;
    border-radius: var(--r-md);
    border: 1px solid var(--line);
    background: var(--surface-2);
    color: var(--text);
    font-family: var(--font-mono);
    font-size: var(--fs-xs);
    line-height: 1.55;
    resize: vertical;
  }
  .bar-end {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
  .split {
    display: grid;
    grid-template-columns: 220px 1fr;
    gap: var(--s-3);
    min-height: 280px;
  }
  .tree {
    display: flex;
    flex-direction: column;
    gap: 8px;
    border-right: 1px solid var(--line);
    padding-right: var(--s-3);
  }
  .tree-head {
    display: flex;
    gap: 6px;
  }
  .mini-in,
  .reg-search {
    flex: 1;
    min-width: 0;
    height: 32px;
    padding: 0 10px;
    border-radius: var(--r-sm);
    border: 1px solid var(--line);
    background: var(--surface);
    color: var(--text);
    font: inherit;
    font-size: var(--fs-xs);
  }
  .tree-list {
    display: grid;
    gap: 8px;
    max-height: 280px;
    overflow-y: auto;
  }
  .grp-h {
    display: flex;
    justify-content: space-between;
    font-size: 11px;
    color: var(--text-3);
    margin-bottom: 2px;
  }
  .del-link {
    border: 0;
    background: none;
    color: var(--bad-text);
    font-size: 11px;
    cursor: pointer;
  }
  .f-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-radius: var(--r-sm);
  }
  .f-row.on {
    background: var(--accent-soft);
  }
  .f-btn {
    flex: 1;
    padding: 5px 8px;
    text-align: left;
    border: 0;
    background: none;
    color: var(--text);
    font-size: var(--fs-xs);
    cursor: pointer;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .del-x {
    padding: 2px 6px;
    border: 0;
    background: none;
    color: var(--text-3);
    cursor: pointer;
  }
  .del-x:hover {
    color: var(--bad-text);
  }
  .editor-col {
    display: grid;
    gap: 8px;
    align-content: start;
  }
  .ed-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    flex-wrap: wrap;
  }
  .row-actions {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .mcp-form {
    display: grid;
    gap: 10px;
    padding: 12px;
    border-radius: var(--r-md);
    border: 1px solid var(--line);
    background: var(--surface-2);
  }
  .grid-2 {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 10px;
  }
  .mcp-list,
  .reg-list {
    margin: 0;
    padding: 0;
    list-style: none;
    display: grid;
    gap: 8px;
    max-height: 320px;
    overflow-y: auto;
  }
  .mcp-list li,
  .reg-list li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 10px 12px;
    border-radius: var(--r-md);
    border: 1px solid var(--line);
    background: var(--surface-2);
  }
  .mcp-info {
    display: grid;
    gap: 3px;
    min-width: 0;
  }
  .mcp-info p {
    margin: 0;
  }
  .mcp-title {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .reg-bar {
    display: flex;
    gap: 8px;
  }
  .repo-link {
    font-size: var(--fs-xs);
    color: var(--accent-text);
    text-decoration: none;
  }
  @media (max-width: 720px) {
    .split,
    .grid-2 {
      grid-template-columns: 1fr;
    }
    .tree {
      border-right: 0;
      border-bottom: 1px solid var(--line);
      padding-right: 0;
      padding-bottom: var(--s-3);
    }
  }
</style>
