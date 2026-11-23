// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * Docker 容器设置五分页工作台抽屉（STEP-05）
 * --------------------------------------------------------------------------
 *   Tab 1: overview  — 概览、生命周期、重启策略免重启热改、可写层提示与反代联动安全删除
 *   Tab 2: network   — Docker 多网络在线热插拔、新建隔离/纯内网 Bridge、端口映射编辑器
 *   Tab 3: proxy     — 缺组件一键补装 (ui.ensure_plugins)、公网端口自动收敛 127.0.0.1、
 *                      自动 ACME / 泛域名证书匹配复用、WebSocket / 自签 HTTPS / 流式大上传
 *   Tab 4: resources — 在线 CPU/内存限额热改、挂载卷持久化审计、敏感环境变量脱敏查看
 *   Tab 5: logs      — 有界尾部日志筛选、行数切换、自动轮询与复制
 *
 * 严格零内联 CSP 合规：0 处 innerHTML、0 处内联 style / on* 事件属性。
 * ========================================================================== */
(() => {
  'use strict';

  /** 零内联 CSP 安全 DOM 构造器 */
  function el(tag, opts = {}, ...children) {
    const node = document.createElement(tag);
    if (opts.cls) node.className = opts.cls;
    if (opts.id) node.id = opts.id;
    if (opts.text !== undefined) node.textContent = String(opts.text);
    if (opts.type) node.type = opts.type;
    if (opts.value !== undefined) node.value = String(opts.value);
    if (opts.placeholder) node.placeholder = opts.placeholder;
    if (opts.checked !== undefined) node.checked = Boolean(opts.checked);
    if (opts.disabled !== undefined) node.disabled = Boolean(opts.disabled);
    if (opts.hidden !== undefined) node.hidden = Boolean(opts.hidden);
    if (opts.href !== undefined) node.href = String(opts.href);
    if (opts.target !== undefined) node.target = String(opts.target);
    if (opts.rel !== undefined) node.rel = String(opts.rel);
    if (opts.attrs) {
      for (const [k, v] of Object.entries(opts.attrs)) {
        const lower = k.toLowerCase();
        if (lower !== 'style' && !lower.startsWith('on')) {
          node.setAttribute(k, String(v));
        }
      }
    }
    if (opts.on) {
      for (const [ev, fn] of Object.entries(opts.on)) {
        node.addEventListener(ev, fn);
      }
    }
    for (const ch of children) {
      if (ch === null || ch === undefined || ch === false) continue;
      node.appendChild(ch instanceof Node ? ch : document.createTextNode(String(ch)));
    }
    return node;
  }

  /** 安全构造 http(s) 链接，拒绝含控制字符或非 http(s) 协议的地址 */
  function buildSafeProxyHref(domain, pathPrefix, tlsMode) {
    const cleanDomain = String(domain || '').trim();
    if (!cleanDomain || /[\s/\\@<>"'`\u0000-\u001f]/.test(cleanDomain)) return null;
    const rawPath = String(pathPrefix || '/').trim() || '/';
    const safePath = rawPath.startsWith('/') ? rawPath : '/' + rawPath;
    if (/[\s<>"'`\u0000-\u001f]/.test(safePath)) return null;
    const scheme = tlsMode === 'off' ? 'http' : 'https';
    return `${scheme}://${cleanDomain}${safePath}`;
  }

  /** 判断某张托管证书是否精确或一级泛域名匹配目标域名 */
  function findMatchingCert(certs, domain) {
    const dom = String(domain || '').trim().toLowerCase().replace(/\.$/, '');
    if (!dom || !Array.isArray(certs)) return null;
    for (const c of certs) {
      for (const san of c.domains || []) {
        if (String(san).trim().toLowerCase().replace(/\.$/, '') === dom) {
          return { cert: c, kind: 'exact' };
        }
      }
    }
    const dot = dom.indexOf('.');
    if (dot > 0) {
      const wantWild = '*' + dom.slice(dot);
      for (const c of certs) {
        for (const san of c.domains || []) {
          if (String(san).trim().toLowerCase().replace(/\.$/, '') === wantWild) {
            return { cert: c, kind: 'wildcard' };
          }
        }
      }
    }
    return null;
  }

  function createContainerSettingsWorkbench(deps) {
    const {
      invoke,
      hostConfirm,
      hostCopy,
      ensurePlugins,
      onListChanged,
      setGlobalStatus,
      onDrawerToggle,
    } = deps;

    let activeContainerId = '';
    let activeTab = 'overview';
    let detail = null;
    let portDrafts = [];
    let logPollTimer = null;
    let busy = false;

    const backdrop = document.getElementById('ct-drawer-backdrop');
    const drawer = document.getElementById('ct-drawer');
    const headerTitle = document.getElementById('ct-drawer-title');
    const headerSub = document.getElementById('ct-drawer-sub');
    const tabBar = document.getElementById('ct-drawer-tabs');
    const feedbackBar = document.getElementById('ct-drawer-feedback');
    const bodyPane = document.getElementById('ct-drawer-body');
    const closeBtn = document.getElementById('ct-drawer-close');

    function stopLogPoll() {
      if (logPollTimer) {
        clearInterval(logPollTimer);
        logPollTimer = null;
      }
    }

    function clearFeedback() {
      if (!feedbackBar) return;
      feedbackBar.hidden = true;
      feedbackBar.textContent = '';
      feedbackBar.className = 'drawer-feedback';
    }

    function showFeedback(level, text) {
      if (setGlobalStatus && text) setGlobalStatus(text);
      if (!feedbackBar || !text) return;
      feedbackBar.className = `drawer-feedback alert-banner ${level}`;
      feedbackBar.textContent = text;
      feedbackBar.hidden = false;
    }

    function closeDrawer() {
      stopLogPoll();
      activeContainerId = '';
      detail = null;
      portDrafts = [];
      clearFeedback();
      if (drawer) drawer.hidden = true;
      if (backdrop) backdrop.hidden = true;
      if (typeof onDrawerToggle === 'function') onDrawerToggle(false);
    }

    closeBtn?.addEventListener('click', closeDrawer);
    backdrop?.addEventListener('click', closeDrawer);
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && drawer && !drawer.hidden) {
        closeDrawer();
      }
    });

    const TABS = [
      { key: 'overview', label: '概览与策略' },
      { key: 'network', label: '网络与端口映射' },
      { key: 'proxy', label: '反向代理与证书' },
      { key: 'resources', label: '资源与存储环境' },
      { key: 'logs', label: '日志与排障' },
    ];

    function renderTabs() {
      if (!tabBar) return;
      tabBar.replaceChildren();
      for (const t of TABS) {
        const btn = el('button', {
          type: 'button',
          cls: activeTab === t.key ? 'tab-btn active' : 'tab-btn',
          text: t.label,
          attrs: { role: 'tab', 'aria-selected': activeTab === t.key ? 'true' : 'false' },
          on: {
            click: () => {
              stopLogPoll();
              clearFeedback();
              activeTab = t.key;
              renderTabs();
              renderActivePane();
            },
          },
        });
        tabBar.appendChild(btn);
      }
    }

    async function guardAction(fn) {
      if (busy) return;
      busy = true;
      clearFeedback();
      try {
        await fn();
      } catch (err) {
        if (err && err.awaitingApproval) {
          showFeedback('info', '操作已提交，请在宿主审批浮窗确认后点击刷新。');
        } else {
          showFeedback('danger', `操作失败：${err?.message || '未知错误'}`);
        }
      } finally {
        busy = false;
      }
    }

    async function loadContainerSettings(containerId, preferredTab, preserveFeedback = false) {
      activeContainerId = containerId;
      if (preferredTab) activeTab = preferredTab;
      if (!preserveFeedback) clearFeedback();
      if (backdrop) backdrop.hidden = false;
      if (drawer) drawer.hidden = false;
      if (typeof onDrawerToggle === 'function') onDrawerToggle(true);
      if (headerTitle) headerTitle.textContent = '正在加载容器配置…';
      if (headerSub) headerSub.textContent = '';
      if (bodyPane) {
        bodyPane.replaceChildren(
          el('div', { cls: 'muted-hint', text: '正在读取容器网络、端口、挂载卷与反向代理状态…' }),
        );
      }
      renderTabs();

      try {
        const res = await invoke('docker.container.settings.get', { id: containerId });
        if (activeContainerId !== containerId) return;
        detail = res || {};
        portDrafts = (detail.port_rules || []).map((r) => ({ ...r }));

        const ct = detail.container || {};
        if (headerTitle) {
          headerTitle.textContent = `${ct.name || ct.short_id || containerId} `;
          headerTitle.appendChild(
            el('span', {
              cls: ct.running ? 'badge ok' : 'badge warn',
              text: ct.state || '-',
            }),
          );
        }
        if (headerSub) {
          headerSub.textContent = `镜像：${ct.image || '-'} · 网络模式：${ct.network_mode || 'bridge'}${
            ct.stack_name ? ' · 所属 Compose 栈：' + ct.stack_name : ''
          }`;
        }
        renderActivePane();
      } catch (err) {
        if (headerTitle) headerTitle.textContent = '加载容器设置失败';
        showFeedback('danger', `加载失败：${err?.message || '未知错误'}`);
        if (bodyPane) {
          bodyPane.replaceChildren(
            el('div', { cls: 'actions' },
              el('button', {
                type: 'button',
                cls: 'btn ghost btn-sm',
                text: '重试加载',
                on: { click: () => void loadContainerSettings(containerId, activeTab) },
              }),
            ),
          );
        }
      }
    }

    function renderActivePane() {
      if (!detail || !bodyPane) return;
      bodyPane.replaceChildren();
      switch (activeTab) {
        case 'overview':
          bodyPane.appendChild(buildOverviewPane());
          break;
        case 'network':
          bodyPane.appendChild(buildNetworkAndPortsPane());
          break;
        case 'proxy':
          bodyPane.appendChild(buildReverseProxyPane());
          break;
        case 'resources':
          bodyPane.appendChild(buildResourcesAndEnvPane());
          break;
        case 'logs':
          bodyPane.appendChild(buildLogsPane());
          break;
      }
    }

    /* ==================== 分页 1：概览与重启策略 ==================== */
    function buildOverviewPane() {
      const ct = detail.container || {};
      const wrap = el('div', { cls: 'drawer-section-stack' });

      if (ct.oom_killed) {
        wrap.appendChild(
          el('div', {
            cls: 'alert-banner danger',
            text: '检测到该容器曾触发内核 OOMKilled（内存超限被强杀）！请前往「资源与存储环境」分页适当调高内存上限或开启系统 Swap。',
          }),
        );
      }

      const dirtyBytes = Number(ct.writable_size_bytes || 0);
      if (dirtyBytes > 0) {
        wrap.appendChild(
          el('div', {
            cls: 'alert-banner info',
            text: `容器可写层检测到 ${(dirtyBytes / (1024 * 1024)).toFixed(2)} MiB 未挂载到外部数据卷的文件改动；修改端口触发无损重建时可自动创建快照镜像保留改动。`,
          }),
        );
      }

      const metaCard = el('div', { cls: 'sub-card' },
        el('h4', { text: '运行生命周期控制' }),
        el('p', {
          cls: 'muted-hint',
          text: `容器完整 ID：${ct.id || '-'} · 镜像：${ct.image || '-'} · 累计异常重启：${ct.restart_count || 0} 次`,
        }),
        el('div', { cls: 'row-actions mt-8' },
          el('button', {
            type: 'button',
            cls: 'btn ghost btn-sm',
            text: '启动',
            disabled: Boolean(ct.running),
            on: { click: () => void runOp('docker.container.action', { id: ct.id, action: 'start' }, '容器已启动') },
          }),
          el('button', {
            type: 'button',
            cls: 'btn ghost btn-sm',
            text: '停止',
            disabled: !ct.running,
            on: { click: () => void runOp('docker.container.action', { id: ct.id, action: 'stop' }, '容器已停止') },
          }),
          el('button', {
            type: 'button',
            cls: 'btn ghost btn-sm',
            text: '重启',
            on: { click: () => void runOp('docker.container.action', { id: ct.id, action: 'restart' }, '容器已重启') },
          }),
          el('button', {
            type: 'button',
            cls: 'btn ghost btn-sm',
            text: '查看实时日志',
            on: {
              click: () => {
                activeTab = 'logs';
                renderTabs();
                renderActivePane();
              },
            },
          }),
        ),
      );

      // 免重建在线修改 RestartPolicy
      const rpSelect = el('select', { cls: 'input-ctrl' },
        el('option', { value: 'no', text: 'no（退出后不自动重启）' }),
        el('option', { value: 'on-failure', text: 'on-failure（仅非零异常退出时重启，最多 5 次）' }),
        el('option', { value: 'unless-stopped', text: 'unless-stopped（开机与崩溃自启，手动停止除外 · 推荐）' }),
        el('option', { value: 'always', text: 'always（始终保持自动重启）' }),
      );
      rpSelect.value = ct.restart_policy || 'no';

      const rpCard = el('div', { cls: 'sub-card' },
        el('h4', { text: '自启与崩溃恢复策略（在线免重启生效）' }),
        el('div', { cls: 'form-inline mt-8' },
          rpSelect,
          el('button', {
            type: 'button',
            cls: 'btn btn-sm',
            text: '保存重启策略',
            on: {
              click: () =>
                void runOp(
                  'docker.container.limits',
                  { id: ct.id, restart_policy: rpSelect.value },
                  '容器重启策略已实时更新',
                ),
            },
          }),
        ),
      );

      // 安全删除区（联动清理反代规则）
      const cleanProxyChk = el('input', { type: 'checkbox', checked: true });
      const linkedCount = (detail.proxy_links || []).length;
      const dangerCard = el('div', { cls: 'sub-card danger-zone' },
        el('h4', { text: '危险操作：移除容器' }),
        el('label', { cls: 'chk-line mt-8' },
          cleanProxyChk,
          ` 同步清理关联的 ${linkedCount} 条反向代理规则（防止遗留 502 死链，保留所有命名数据卷）`,
        ),
        el('div', { cls: 'actions' },
          el('button', {
            type: 'button',
            cls: 'btn danger btn-sm',
            text: '删除此容器',
            on: {
              click: () =>
                void guardAction(async () => {
                  const ok = await hostConfirm(
                    '删除容器',
                    `确认删除容器「${ct.name || ct.short_id}」？已挂载的数据卷不会被删除。`,
                    { danger: true, confirmLabel: '确认删除' },
                  );
                  if (!ok) return;
                  await invoke('docker.container.remove', {
                    id: ct.id,
                    force: true,
                    cleanup_linked_proxies: cleanProxyChk.checked,
                  });
                  setGlobalStatus(`已删除容器 ${ct.name || ct.short_id}`);
                  closeDrawer();
                  await onListChanged();
                }),
            },
          }),
        ),
      );

      wrap.append(metaCard, rpCard, dangerCard);
      return wrap;
    }

    /* ==================== 分页 2：网络与端口映射（核心分页） ==================== */
    function buildNetworkAndPortsPane() {
      const ct = detail.container || {};
      const isSpecialNet =
        ct.network_mode === 'host' ||
        ct.network_mode === 'none' ||
        String(ct.network_mode || '').startsWith('container:');
      const wrap = el('div', { cls: 'drawer-section-stack' });

      /* --- 上半区：Docker 网络连接与新建隔离网络 --- */
      const netCard = el('div', { cls: 'sub-card' },
        el('h4', { text: '1. 容器所属 Docker 网络（支持多网络在线热插拔，无需重启容器）' }),
      );

      if (isSpecialNet) {
        netCard.appendChild(
          el('div', {
            cls: 'alert-banner warn mt-8',
            text: `当前容器采用特殊网络模式「${ct.network_mode}」：与宿主机或目标容器直接共享网络栈，Docker 不支持动态插拔 Bridge 网络或配置端口映射。`,
          }),
        );
      } else {
        const connectedNets = detail.networks_connected || [];
        if (connectedNets.some((n) => n.name === 'bridge') && connectedNets.length === 1) {
          netCard.appendChild(
            el('div', {
              cls: 'muted-hint mt-8',
              text: '提示：默认 bridge 网络不支持按容器名 DNS 互访。若需让 Web 容器连接 MySQL/Redis 容器，建议在下方新建并接入「自定义隔离网络」，数据库无需映射任何宿主机端口即可通过别名安全内网通信。',
            }),
          );
        }

        const netTable = el('table', { cls: 'compact-table' },
          el('thead', {},
            el('tr', {},
              el('th', { text: '网络名称' }),
              el('th', { text: '容器内网 IP' }),
              el('th', { text: '容器内 DNS 别名 (Aliases)' }),
              el('th', { text: '操作' }),
            ),
          ),
        );
        const netTbody = el('tbody');
        for (const n of connectedNets) {
          const isLastNet = connectedNets.length <= 1;
          const disBtn = el('button', {
            type: 'button',
            cls: 'btn danger btn-sm',
            text: '断开',
            disabled: isLastNet,
            attrs: {
              title: isLastNet
                ? 'LAST_NETWORK_PROTECTED：至少需保留一个网络，请先接入新网络再断开旧网络'
                : '从该网络断开容器',
            },
            on: {
              click: () =>
                void runOp(
                  'docker.network.membership',
                  { container_id: ct.id, network_id: n.name, action: 'disconnect' },
                  `已断开网络 ${n.name}`,
                ),
            },
          });
          netTbody.appendChild(
            el('tr', {},
              el('td', { text: `${n.name}${n.internal ? ' [纯内网禁外连]' : ''}` }),
              el('td', { cls: 'mono-val', text: [n.ipv4, n.ipv6].filter(Boolean).join(' / ') || '-' }),
              el('td', { cls: 'mono-val', text: (n.aliases || []).join(', ') || ct.name || '-' }),
              el('td', {}, disBtn),
            ),
          );
        }
        netTable.appendChild(netTbody);
        netCard.appendChild(netTable);

        // 接入现有网络表单
        const availSelect = el('select', { cls: 'input-ctrl' });
        const connectedSet = new Set(connectedNets.map((n) => n.name));
        let availCount = 0;
        for (const an of detail.networks_all || []) {
          if (an.name === 'host' || an.name === 'none' || connectedSet.has(an.name)) continue;
          availCount++;
          availSelect.appendChild(
            el('option', {
              value: an.name,
              text: `${an.name} (${an.subnet || an.driver || 'bridge'}${an.internal ? ' · 纯内网' : ''})`,
            }),
          );
        }
        if (availCount === 0) {
          availSelect.appendChild(el('option', { value: '', text: '暂无其它可接入网络（可在下方新建）' }));
        }
        const aliasInput = el('input', { cls: 'input-ctrl', placeholder: '可选 DNS 别名（如 db, redis，逗号分隔）' });
        const staticIPInput = el('input', { cls: 'input-ctrl', placeholder: '可选静态 IPv4（留空自动分配）' });

        netCard.appendChild(
          el('div', { cls: 'form-grid mt-12' },
            el('label', {}, '接入已有网络', availSelect),
            el('label', {}, '网络内 DNS 别名', aliasInput),
            el('label', {}, '指定静态内网 IP', staticIPInput),
          ),
        );
        netCard.appendChild(
          el('div', { cls: 'actions' },
            el('button', {
              type: 'button',
              cls: 'btn ghost btn-sm',
              text: '+ 在线接入所选网络',
              disabled: availCount === 0,
              on: {
                click: () => {
                  if (!availSelect.value) return;
                  const aliases = aliasInput.value
                    .split(',')
                    .map((s) => s.trim())
                    .filter(Boolean);
                  const payload = {
                    container_id: ct.id,
                    network_id: availSelect.value,
                    action: 'connect',
                    aliases,
                  };
                  const ipv4 = staticIPInput.value.trim();
                  if (ipv4) payload.ipv4_address = ipv4;
                  void runOp('docker.network.membership', payload, `已在线接入网络 ${availSelect.value}`);
                },
              },
            }),
          ),
        );

        // 折叠式快速新建隔离网络表单
        const newNetName = el('input', { cls: 'input-ctrl', placeholder: '如 app-isolated-net' });
        const newNetInternal = el('input', { type: 'checkbox' });
        const newNetIPv6 = el('input', { type: 'checkbox' });
        netCard.appendChild(
          el('details', { cls: 'mt-12' },
            el('summary', { cls: 'clickable-summary', text: '+ 没有合适的网络？原地新建隔离 Docker Bridge 网络' }),
            el('div', { cls: 'form-grid mt-8' },
              el('label', {}, '新网络名称', newNetName),
              el('label', { cls: 'chk-line' }, newNetInternal, ' 纯内网模式 (internal：禁止容器访问公网，推荐给数据库/缓存)'),
              el('label', { cls: 'chk-line' }, newNetIPv6, ' 启用 IPv6 容器子网'),
            ),
            el('div', { cls: 'actions' },
              el('button', {
                type: 'button',
                cls: 'btn ghost btn-sm',
                text: '创建网络并立即接入当前容器',
                on: {
                  click: () => {
                    const name = newNetName.value.trim();
                    if (!name) {
                      showFeedback('warn', '请先填写新网络名称（仅支持字母、数字、连字符和下划线）');
                      return;
                    }
                    void runOp(
                      'docker.network.create',
                      {
                        name,
                        internal: newNetInternal.checked,
                        enable_ipv6: newNetIPv6.checked,
                        attach_container_id: ct.id,
                      },
                      `隔离网络 ${name} 已创建并接入容器`,
                    );
                  },
                },
              }),
            ),
          ),
        );
      }

      /* --- 下半区：端口映射编辑器（127.0.0.1 回环 vs 0.0.0.0 公网 vs 指定网卡 IP） --- */
      const portCard = el('div', { cls: 'sub-card' },
        el('h4', { text: '2. 宿主机端口映射设置（隐身本机回环 vs 公网开放访问）' }),
      );

      if (!isSpecialNet) {
        const exposedList = detail.image_exposed_ports || [];
        if (exposedList.length > 0) {
          const chipRow = el('div', { cls: 'chip-row mt-8' },
            el('span', { cls: 'muted-hint', text: '镜像内部声明端口（点击一键添加回环映射）：' }),
          );
          for (const exp of exposedList) {
            const [pNum, pProto] = String(exp).split('/');
            chipRow.appendChild(
              el('button', {
                type: 'button',
                cls: 'chip-btn',
                text: `+ 容器端口 ${pNum}/${pProto || 'tcp'}`,
                on: {
                  click: () => {
                    portDrafts.push({
                      bind_mode: 'loopback',
                      bind_ip: '127.0.0.1',
                      host_port: 0,
                      container_port: Number(pNum),
                      protocol: pProto || 'tcp',
                      include_ipv6: false,
                    });
                    renderActivePane();
                  },
                },
              }),
            );
          }
          portCard.appendChild(chipRow);
        }

        const hasPublicRule = portDrafts.some((r) => r.bind_mode === 'public');
        if (hasPublicRule) {
          portCard.appendChild(
            el('div', {
              cls: 'alert-banner warn mt-8',
              text: '安全提醒：您配置了「公网开放 (0.0.0.0)」规则。Docker 公网端口转发走内核 FORWARD 链，会绕过常规 INPUT 防火墙直接对公网暴露！若该端口运行的是网页/管理后台，强烈建议改为「仅本机回环 (127.0.0.1)」并在隔壁「反向代理与证书」分页绑定域名安全访问。',
            }),
          );
        }

        const rawBindable = detail.host_bindable_ips || detail.bindable_ips || [];
        const bindableIPs = rawBindable.filter((x) => x.ip !== '127.0.0.1' && x.ip !== '0.0.0.0');
        const rowsBox = el('div', { cls: 'port-rules-list mt-10' });

        if (portDrafts.length === 0) {
          rowsBox.appendChild(
            el('p', { cls: 'muted-hint', text: '当前无宿主机端口映射（容器仅在 Docker 内网可达）。点击下方按钮添加映射规则。' }),
          );
        }

        portDrafts.forEach((rule, idx) => {
          const modeSel = el('select', { cls: 'input-ctrl mode-sel' },
            el('option', { value: 'loopback', text: '仅本机回环 (127.0.0.1 · 推荐)' }),
            el('option', { value: 'public', text: '公网直连 (0.0.0.0 · 暴露公网)' }),
            el('option', { value: 'specific_ip', text: '指定本机网卡/组网 IP' }),
          );
          modeSel.value = rule.bind_mode || 'loopback';

          const specificSel = el('select', { cls: 'input-ctrl', hidden: modeSel.value !== 'specific_ip' });
          if (bindableIPs.length === 0) {
            specificSel.appendChild(el('option', { value: '', text: '无额外可用网卡 IP' }));
          } else {
            for (const item of bindableIPs) {
              specificSel.appendChild(el('option', { value: item.ip, text: item.label || item.ip }));
            }
          }
          if (rule.bind_ip && modeSel.value === 'specific_ip') specificSel.value = rule.bind_ip;

          modeSel.addEventListener('change', () => {
            rule.bind_mode = modeSel.value;
            if (rule.bind_mode === 'loopback') rule.bind_ip = '127.0.0.1';
            else if (rule.bind_mode === 'public') rule.bind_ip = '0.0.0.0';
            else rule.bind_ip = specificSel.value || '';
            renderActivePane();
          });
          specificSel.addEventListener('change', () => {
            rule.bind_ip = specificSel.value;
          });

          const hostPortInput = el('input', {
            type: 'number',
            cls: 'input-ctrl port-num',
            value: rule.host_port > 0 ? rule.host_port : '',
            placeholder: '0/留空=自动分配',
            attrs: { min: '0', max: '65535' },
            on: { input: (e) => { rule.host_port = Number(e.target.value || 0); } },
          });

          const containerPortInput = el('input', {
            type: 'number',
            cls: 'input-ctrl port-num',
            value: rule.container_port || '',
            placeholder: '容器端口 (如 80)',
            attrs: { min: '1', max: '65535' },
            on: { input: (e) => { rule.container_port = Number(e.target.value || 0); } },
          });

          const protoSel = el('select', { cls: 'input-ctrl proto-sel' },
            el('option', { value: 'tcp', text: 'TCP' }),
            el('option', { value: 'udp', text: 'UDP' }),
            el('option', { value: 'both', text: 'TCP + UDP' }),
          );
          protoSel.value = rule.protocol || 'tcp';
          protoSel.addEventListener('change', () => { rule.protocol = protoSel.value; });

          const v6Chk = el('input', {
            type: 'checkbox',
            checked: Boolean(rule.include_ipv6),
            disabled: rule.bind_mode === 'specific_ip',
            on: { change: (e) => { rule.include_ipv6 = e.target.checked; } },
          });

          const modeBadge = el('span', {
            cls:
              rule.bind_mode === 'public'
                ? 'bind-pill bind-public'
                : rule.bind_mode === 'specific_ip'
                  ? 'bind-pill bind-specific'
                  : 'bind-pill bind-loopback',
            text: rule.bind_mode === 'public' ? '公网暴露' : rule.bind_mode === 'specific_ip' ? '指定网卡' : '回环推荐',
          });

          const delRuleBtn = el('button', {
            type: 'button',
            cls: 'btn danger btn-sm',
            text: '移除',
            on: {
              click: () => {
                portDrafts.splice(idx, 1);
                renderActivePane();
              },
            },
          });

          rowsBox.appendChild(
            el('div', { cls: 'port-rule-row' },
              modeBadge,
              modeSel,
              specificSel,
              hostPortInput,
              el('span', { cls: 'arrow-sep', text: '→ 容器' }),
              containerPortInput,
              protoSel,
              el('label', { cls: 'chk-inline', attrs: { title: '同步绑定 IPv6 (::1 或 ::)' } }, v6Chk, 'IPv6'),
              delRuleBtn,
            ),
          );
        });

        portCard.appendChild(rowsBox);
        portCard.appendChild(
          el('div', { cls: 'actions mt-8' },
            el('button', {
              type: 'button',
              cls: 'btn ghost btn-sm',
              text: '+ 新增端口映射规则',
              on: {
                click: () => {
                  portDrafts.push({
                    bind_mode: 'loopback',
                    bind_ip: '127.0.0.1',
                    host_port: 0,
                    container_port: 80,
                    protocol: 'tcp',
                    include_ipv6: false,
                  });
                  renderActivePane();
                },
              },
            }),
          ),
        );

        const dirtyBytes = Number(ct.writable_size_bytes || 0);
        const commitChk = el('input', { type: 'checkbox', checked: !ct.stack_name && dirtyBytes > 0 });
        if (!ct.stack_name && dirtyBytes > 0) {
          portCard.appendChild(
            el('div', { cls: 'alert-banner info mt-10' },
              el('label', { cls: 'chk-line' },
                commitChk,
                ` 检测到容器系统层有 ${(dirtyBytes / (1024 * 1024)).toFixed(2)} MiB 未挂载到外部卷的文件改动，重建前自动保存快照镜像（100% 防止未挂卷数据丢失）`,
              ),
            ),
          );
        }

        const applyHint = ct.stack_name
          ? `受管 Compose 栈「${ct.stack_name}」：保存后将自动精准改写 compose.yml 并平滑重建该服务容器（数据卷完整保留，关联反代上游端口自动同步更新）。`
          : '独立容器无损 Saga 重建：前置端口冲突预检 → 停旧改名热备 → 建新恢复全量挂载卷与多网络 → 失败秒级自动回滚原容器，并自动同步刷新关联反代端口。';

        portCard.appendChild(el('p', { cls: 'muted-hint mt-8', text: applyHint }));
        portCard.appendChild(
          el('div', { cls: 'actions' },
            el('button', {
              type: 'button',
              cls: 'btn',
              text: '应用端口映射设置',
              on: {
                click: () =>
                  void guardAction(async () => {
                    for (let i = 0; i < portDrafts.length; i++) {
                      const r = portDrafts[i];
                      if (!Number.isInteger(r.container_port) || r.container_port < 1 || r.container_port > 65535) {
                        showFeedback('warn', `第 ${i + 1} 条规则的容器内部端口必须为 1..65535`);
                        return;
                      }
                      if (r.bind_mode === 'specific_ip' && !r.bind_ip) {
                        showFeedback('warn', `第 ${i + 1} 条规则请选择要绑定的本机网卡 IP`);
                        return;
                      }
                    }
                    const res = await invoke('docker.container.ports.apply', {
                      container_id: ct.id,
                      rules: portDrafts.map((r) => ({
                        bind_mode: r.bind_mode || 'loopback',
                        bind_ip: r.bind_ip || (r.bind_mode === 'public' ? '0.0.0.0' : '127.0.0.1'),
                        host_port: Number(r.host_port || 0),
                        container_port: Number(r.container_port),
                        protocol: r.protocol || 'tcp',
                        include_ipv6: Boolean(r.include_ipv6),
                      })),
                      commit_writable_layer: Boolean(commitChk.checked),
                      allow_discard_writable_layer: !commitChk.checked,
                    });
                    const nextId = res.new_container_id || ct.id;
                    await onListChanged();
                    await loadContainerSettings(nextId, 'network', true);
                    showFeedback('ok', '端口映射已无损更新并生效，关联反代上游端口已自动同步。');
                  }),
              },
            }),
          ),
        );
      }

      wrap.append(netCard, portCard);
      return wrap;
    }

    /* ==================== 分页 3：反向代理与自动证书 ==================== */
    function buildReverseProxyPane() {
      const ct = detail.container || {};
      const readiness = detail.proxy_readiness || {};
      const links = detail.proxy_links || [];
      const wrap = el('div', { cls: 'drawer-section-stack' });

      const runEnsurePlugins = async (ids, reason) => {
        await guardAction(async () => {
          const res = await ensurePlugins(ids, reason);
          if (res?.cancelled) {
            showFeedback('info', '已取消启用官方联动组件。');
            return;
          }
          if (res && !res.ready) {
            const failMsg = (res.failed || []).map((f) => `${f.plugin_id}: ${f.detail}`).join('；');
            showFeedback('warn', failMsg || '部分官方组件尚未就绪，请检查应用中心状态。');
            return;
          }
          await loadContainerSettings(ct.id, 'proxy', true);
          showFeedback('ok', '官方反向代理与证书组件已启用就绪！');
        });
      };

      // 1. 组件缺失时展示免跳页一键安装启用卡片
      if (!readiness.ingress_installed) {
        const missingList =
          Array.isArray(readiness.missing_plugins) && readiness.missing_plugins.length > 0
            ? readiness.missing_plugins
            : ['web.ingress', 'tls.certificates'];
        wrap.appendChild(
          el('div', { cls: 'sub-card highlight-card' },
            el('h4', { text: '尚未启用轻量反向代理网关组件 (web.ingress)' }),
            el('p', {
              cls: 'muted-hint mt-8',
              text: '容器域名反代与自动续期 HTTPS 直接借用面板官方 web.ingress 与 tls.certificates 组件，无需在 Docker 内额外运行占内存的 Nginx / NPM 容器。',
            }),
            el('div', { cls: 'actions' },
              el('button', {
                type: 'button',
                cls: 'btn',
                text: '⚡ 一键安装并启用反向代理与自动证书组件',
                on: {
                  click: () =>
                    void runEnsurePlugins(
                      missingList,
                      `为容器「${ct.name || ct.short_id}」启用域名反向代理与自动 HTTPS 证书能力`,
                    ),
                },
              }),
            ),
          ),
        );
        return wrap;
      }

      if (!readiness.certs_installed) {
        wrap.appendChild(
          el('div', { cls: 'alert-banner info banner-row' },
            el('span', { text: '提示：尚未启用 tls.certificates 组件，当前仅可使用纯 HTTP 反代；如需自动申请并续期 HTTPS 证书：' }),
            el('button', {
              type: 'button',
              cls: 'btn ghost btn-sm',
              text: '一键补装自动证书组件',
              on: {
                click: () =>
                  void runEnsurePlugins(
                    ['tls.certificates'],
                    `为容器「${ct.name || ct.short_id}」启用自动 HTTPS 证书管理`,
                  ),
              },
            }),
          ),
        );
      }

      // 2. 当前容器已绑定的反代域名列表
      const listCard = el('div', { cls: 'sub-card' }, el('h4', { text: '当前容器已绑定的域名反代列表' }));
      if (links.length === 0) {
        listCard.appendChild(
          el('p', { cls: 'muted-hint mt-8', text: '暂未给此容器绑定任何域名。在下方填写域名即可一键打通反代与 HTTPS 自动续期。' }),
        );
      } else {
        const tbl = el('table', { cls: 'compact-table' },
          el('thead', {},
            el('tr', {},
              el('th', { text: '访问域名与路径' }),
              el('th', { text: '转发目标 (本机回环)' }),
              el('th', { text: 'HTTPS / 证书' }),
              el('th', { text: '操作' }),
            ),
          ),
        );
        const tb = el('tbody');
        for (const lk of links) {
          const safeHref = buildSafeProxyHref(lk.domain, lk.path_prefix, lk.tls_mode);
          const displayUrl = `${lk.tls_mode === 'off' ? 'http' : 'https'}://${lk.domain}${lk.path_prefix || '/'}`;
          const domainCell = safeHref
            ? el('a', { cls: 'proxy-pill', href: safeHref, target: '_blank', rel: 'noopener noreferrer', text: displayUrl })
            : el('span', { text: displayUrl });

          tb.appendChild(
            el('tr', {},
              el('td', {}, domainCell),
              el('td', { cls: 'mono-val', text: `${lk.upstream_scheme || 'http'}://${lk.host_bind_ip}:${lk.host_port} (容器:${lk.container_port})` }),
              el('td', { text: lk.tls_mode === 'off' ? '纯 HTTP' : `HTTPS (${lk.cert_id || '自动续期'})` }),
              el('td', { cls: 'row-actions' },
                el('button', {
                  type: 'button',
                  cls: 'btn ghost btn-sm',
                  text: '复制链接',
                  on: { click: () => void guardAction(() => hostCopy(displayUrl, '已复制访问地址')) },
                }),
                el('button', {
                  type: 'button',
                  cls: 'btn danger btn-sm',
                  text: '解绑移除',
                  on: {
                    click: () =>
                      void guardAction(async () => {
                        const ok = await hostConfirm(
                          '移除容器域名反代',
                          `确认解绑域名 ${lk.domain}${lk.path_prefix || '/'}？容器自身不会受影响。`,
                          { danger: true, confirmLabel: '确认解绑' },
                        );
                        if (!ok) return;
                        await invoke('docker.container.proxy.delete', { link_id: lk.id });
                        await onListChanged();
                        await loadContainerSettings(ct.id, 'proxy', true);
                        showFeedback('ok', `已解绑域名 ${lk.domain}`);
                      }),
                  },
                }),
              ),
            ),
          );
        }
        tbl.appendChild(tb);
        listCard.appendChild(tbl);
      }

      // 3. 新增容器反代与证书智能表单
      const portStratSel = el('select', { cls: 'input-ctrl' });
      const currentRules = detail.port_rules || [];
      const exposedPorts = detail.image_exposed_ports || [];

      for (const r of currentRules) {
        if (r.protocol === 'udp') continue;
        if (r.bind_mode === 'loopback') {
          portStratSel.appendChild(
            el('option', {
              value: `use_existing:${r.container_port}:${r.host_port}`,
              text: `使用已映射安全回环 127.0.0.1:${r.host_port} → 容器:${r.container_port}（推荐）`,
            }),
          );
        } else if (r.bind_mode === 'public') {
          portStratSel.appendChild(
            el('option', {
              value: `converge_loopback:${r.container_port}:${r.host_port}`,
              text: `将公网裸露 0.0.0.0:${r.host_port} 自动收敛为 127.0.0.1:${r.host_port} 并绑反代（强烈推荐）`,
            }),
          );
          portStratSel.appendChild(
            el('option', {
              value: `use_existing:${r.container_port}:${r.host_port}`,
              text: `保留公网暴露并反代 127.0.0.1:${r.host_port} → 容器:${r.container_port}`,
            }),
          );
        }
      }
      for (const exp of exposedPorts) {
        const [pNum, pProto] = String(exp).split('/');
        if (pProto === 'udp') continue;
        if (!currentRules.some((r) => Number(r.container_port) === Number(pNum))) {
          portStratSel.appendChild(
            el('option', {
              value: `auto_map_loopback:${pNum}:0`,
              text: `自动映射空闲 127.0.0.1 端口 → 容器未映射端口 ${pNum} 并绑反代`,
            }),
          );
        }
      }
      portStratSel.appendChild(
        el('option', {
          value: 'custom_port:0:0',
          text: '手动输入容器内部端口号（自动分配 127.0.0.1 回环端口）…',
        }),
      );

      const manualContainerPort = el('input', {
        type: 'number',
        cls: 'input-ctrl',
        placeholder: '输入容器内部监听端口（如 8080）',
        attrs: { min: '1', max: '65535' },
        hidden: !portStratSel.value.startsWith('custom_port:'),
      });
      portStratSel.addEventListener('change', () => {
        manualContainerPort.hidden = !portStratSel.value.startsWith('custom_port:');
      });

      const domainInput = el('input', { cls: 'input-ctrl', placeholder: '如 alist.example.com' });
      const pathInput = el('input', { cls: 'input-ctrl', value: '/', placeholder: '/（支持同域名多路径如 /api）' });

      const certMatchHint = el('div', { cls: 'cert-match-hint', hidden: true });
      const updateCertMatchHint = () => {
        const matched = findMatchingCert(readiness.available_certs, domainInput.value);
        if (!matched) {
          certMatchHint.hidden = true;
          certMatchHint.textContent = '';
          return;
        }
        const label = matched.kind === 'wildcard' ? '命中已有泛域名证书' : '命中已有精确证书';
        certMatchHint.textContent = `${label}：${(matched.cert.domains || []).join(', ')}（到期 ${matched.cert.expires_at || '-'}），自动复用无需重复签发。`;
        certMatchHint.hidden = false;
      };
      domainInput.addEventListener('input', updateCertMatchHint);

      const certStratSel = el('select', { cls: 'input-ctrl' });
      if (readiness.certs_installed) {
        certStratSel.appendChild(
          el('option', { value: 'auto_acme', text: '自动申请并续期 HTTPS 证书（命中泛域名证书自动复用）' }),
        );
        if ((readiness.available_certs || []).length > 0) {
          certStratSel.appendChild(
            el('option', { value: 'existing_cert', text: '手动指定面板中已有的托管证书 / 泛域名证书' }),
          );
        }
      }
      certStratSel.appendChild(
        el('option', { value: 'http_only', text: '纯 HTTP 反代（前方已有 Cloudflare Tunnel / CDN 卸载 HTTPS）' }),
      );

      const existingCertSel = el('select', { cls: 'input-ctrl', hidden: true });
      for (const c of readiness.available_certs || []) {
        existingCertSel.appendChild(
          el('option', {
            value: c.cert_id,
            text: `${(c.domains || []).join(', ')} (${c.issuer || 'ACME'} · 到期 ${c.expires_at || '-'})`,
          }),
        );
      }
      certStratSel.addEventListener('change', () => {
        existingCertSel.hidden = certStratSel.value !== 'existing_cert';
      });

      const schemeSel = el('select', { cls: 'input-ctrl' },
        el('option', { value: 'http', text: 'http://（99% 容器默认）' }),
        el('option', { value: 'https_insecure', text: 'https://（容器内部为自签 HTTPS，如 Portainer 9443）' }),
      );
      const wsChk = el('input', { type: 'checkbox', checked: true });
      const maxBodyInput = el('input', {
        type: 'number',
        cls: 'input-ctrl',
        value: '0',
        attrs: { min: '0', max: '65536' },
        placeholder: '0 = 不限体积流式上传（网盘推荐 0）',
      });
      const rpsInput = el('input', {
        type: 'number',
        cls: 'input-ctrl',
        value: '0',
        attrs: { min: '0', max: '100000' },
        placeholder: '0 = 不限速',
      });
      const authUserInput = el('input', { cls: 'input-ctrl', placeholder: '可选：访问密码保护用户名' });
      const authPassInput = el('input', { type: 'password', cls: 'input-ctrl', placeholder: '可选：访问密码保护口令' });

      const dirtyBytes = Number(ct.writable_size_bytes || 0);
      const proxyCommitChk = el('input', { type: 'checkbox', checked: !ct.stack_name && dirtyBytes > 0 });

      const formCard = el('div', { cls: 'sub-card' },
        el('h4', { text: '+ 为当前容器绑定域名反向代理与自动证书' }),
        el('div', { cls: 'form-grid' },
          el('label', {}, '容器端口与公网收敛策略', portStratSel),
          manualContainerPort,
          el('label', {}, '绑定域名', domainInput),
          el('label', {}, 'URL 路径前缀', pathInput),
          el('label', {}, 'HTTPS 证书与自动续期策略', certStratSel),
          existingCertSel,
          el('label', {}, '容器内部上游协议', schemeSel),
          el('label', {}, '最大请求/上传体积 (MiB，0=流式不限)', maxBodyInput),
          el('label', {}, '单 IP 每秒限流 RPS (0=不限)', rpsInput),
          el('label', {}, '可选 BasicAuth 访问账号', authUserInput),
          el('label', {}, '可选 BasicAuth 访问密码', authPassInput),
        ),
        certMatchHint,
        el('label', { cls: 'chk-line mt-8' }, wsChk, ' 开启 WebSocket 实时长连接透传（Uptime Kuma / Vaultwarden / 在线终端必开）'),
        !ct.stack_name && dirtyBytes > 0
          ? el('label', { cls: 'chk-line mt-8' },
              proxyCommitChk,
              ` 触发端口收敛/自动映射重建前自动快照容器未挂卷改动 (${(dirtyBytes / (1024 * 1024)).toFixed(2)} MiB)`,
            )
          : null,
        el('div', { cls: 'actions mt-12' },
          el('button', {
            type: 'button',
            cls: 'btn',
            text: '保存并启用容器反向代理',
            on: {
              click: () =>
                void guardAction(async () => {
                  const domain = domainInput.value.trim();
                  if (!domain) {
                    showFeedback('warn', '请先填写要绑定的域名（如 app.example.com）');
                    return;
                  }
                  const [strat, cPortStr, hPortStr] = portStratSel.value.split(':');
                  const cPort = strat === 'custom_port' ? Number(manualContainerPort.value) : Number(cPortStr);
                  if (!Number.isInteger(cPort) || cPort < 1 || cPort > 65535) {
                    showFeedback('warn', '请填写有效的容器内部端口 (1..65535)');
                    return;
                  }
                  const actualStrat = strat === 'custom_port' ? 'auto_map_loopback' : strat;
                  const isHttpsUpstream = schemeSel.value === 'https_insecure';

                  const payload = {
                    container_id: ct.id,
                    container_port: cPort,
                    upstream_port_strategy: actualStrat,
                    existing_host_port: Number(hPortStr || 0),
                    domain,
                    path_prefix: pathInput.value.trim() || '/',
                    upstream_scheme: isHttpsUpstream ? 'https' : 'http',
                    upstream_insecure: isHttpsUpstream,
                    websocket: wsChk.checked,
                    max_body_mb: Number(maxBodyInput.value || 0),
                    rate_limit_rps: Number(rpsInput.value || 0),
                    basic_auth_user: authUserInput.value.trim(),
                    basic_auth_pass: authPassInput.value,
                    cert_strategy: certStratSel.value,
                    existing_cert_id: certStratSel.value === 'existing_cert' ? existingCertSel.value : '',
                  };
                  if (actualStrat !== 'use_existing' && proxyCommitChk.checked) {
                    payload.commit_writable_layer = true;
                  }

                  const res = await invoke('docker.container.proxy.upsert', payload);
                  const nextId = res.new_container_id || ct.id;
                  await onListChanged();
                  await loadContainerSettings(nextId, 'proxy', true);
                  showFeedback('ok', `域名 ${domain} 反向代理配置已生效！`);
                }),
            },
          }),
        ),
      );

      wrap.append(listCard, formCard);
      return wrap;
    }

    /* ==================== 分页 4：资源限额、挂载卷与脱敏环境变量 ==================== */
    function buildResourcesAndEnvPane() {
      const ct = detail.container || {};
      const wrap = el('div', { cls: 'drawer-section-stack' });

      const memInput = el('input', {
        type: 'number',
        cls: 'input-ctrl',
        value: ct.memory_limit_mb > 0 ? Math.round(ct.memory_limit_mb) : '',
        placeholder: '留空不修改 (16..65536 MiB)',
        attrs: { min: '16', max: '65536' },
      });
      const cpuInput = el('input', {
        type: 'number',
        cls: 'input-ctrl',
        value: ct.cpus_limit > 0 ? ct.cpus_limit : '',
        placeholder: '留空不修改 (如 0.5, 1, 2)',
        attrs: { step: '0.1', min: '0.1', max: '64' },
      });

      const resCard = el('div', { cls: 'sub-card' },
        el('h4', { text: '1. 动态资源限额（在线热生效，无需重启容器）' }),
        el('p', {
          cls: 'muted-hint mt-8',
          text: `当前实时内存：${Number(ct.memory_mb || 0).toFixed(1)} MiB · 当前实时 CPU：${Number(ct.cpu_percent || 0).toFixed(1)}%`,
        }),
        el('div', { cls: 'form-grid' },
          el('label', {}, '内存硬上限 (MiB)', memInput),
          el('label', {}, 'CPU 核数上限', cpuInput),
        ),
        el('div', { cls: 'actions' },
          el('button', {
            type: 'button',
            cls: 'btn btn-sm',
            text: '更新资源限额',
            on: {
              click: () => {
                const payload = { id: ct.id };
                if (memInput.value.trim() !== '') payload.memory_mb = Number(memInput.value);
                if (cpuInput.value.trim() !== '') payload.cpus = Number(cpuInput.value);
                if (payload.memory_mb === undefined && payload.cpus === undefined) {
                  showFeedback('warn', '请至少填写内存上限或 CPU 核数上限之一');
                  return;
                }
                void runOp('docker.container.limits', payload, '资源限额已热生效');
              },
            },
          }),
        ),
      );

      // 存储卷列表
      const mounts = detail.mounts || [];
      const volCard = el('div', { cls: 'sub-card' }, el('h4', { text: '2. 存储卷与宿主机路径挂载清单（只读审计）' }));
      if (mounts.length === 0) {
        volCard.appendChild(
          el('p', { cls: 'muted-hint mt-8', text: '当前容器未挂载任何外部 Volume 或宿主机目录（容器删除后内部文件将不保留）。' }),
        );
      } else {
        const mTbl = el('table', { cls: 'compact-table' },
          el('thead', {},
            el('tr', {},
              el('th', { text: '类型' }),
              el('th', { text: '宿主机源 / 卷名' }),
              el('th', { text: '容器内路径' }),
              el('th', { text: '权限' }),
            ),
          ),
        );
        const mTb = el('tbody');
        for (const m of mounts) {
          mTb.appendChild(
            el('tr', {},
              el('td', { text: m.type || 'bind' }),
              el('td', { cls: 'mono-val', text: m.source || m.name || '-' }),
              el('td', { cls: 'mono-val', text: m.destination || '-' }),
              el('td', { text: m.rw ? '读写 (RW)' : '只读 (RO)' }),
            ),
          );
        }
        mTbl.appendChild(mTb);
        volCard.appendChild(mTbl);
      }

      // 环境变量脱敏查看器
      const envs = detail.env || [];
      const envCard = el('div', { cls: 'sub-card' }, el('h4', { text: '3. 容器运行环境变量（敏感口令默认遮罩）' }));
      if (envs.length === 0) {
        envCard.appendChild(el('p', { cls: 'muted-hint mt-8', text: '无环境变量记录。' }));
      } else {
        const eTbl = el('table', { cls: 'compact-table' },
          el('thead', {},
            el('tr', {},
              el('th', { text: '变量名' }),
              el('th', { text: '值' }),
              el('th', { text: '操作' }),
            ),
          ),
        );
        const eTb = el('tbody');
        for (const item of envs) {
          const eqIdx = String(item).indexOf('=');
          const k = eqIdx >= 0 ? String(item).slice(0, eqIdx) : String(item);
          const v = eqIdx >= 0 ? String(item).slice(eqIdx + 1) : '';
          const isSensitive = /pass|secret|token|key|pwd|auth/i.test(k);
          let revealed = !isSensitive;
          const valSpan = el('span', { cls: 'mono-val', text: revealed ? v : '••••••••••••' });
          const toggleBtn = isSensitive
            ? el('button', {
                type: 'button',
                cls: 'btn ghost btn-sm',
                text: '显示',
                on: {
                  click: (e) => {
                    revealed = !revealed;
                    valSpan.textContent = revealed ? v : '••••••••••••';
                    e.currentTarget.textContent = revealed ? '隐藏' : '显示';
                  },
                },
              })
            : null;
          eTb.appendChild(
            el('tr', {},
              el('td', { cls: 'mono-val', text: k }),
              el('td', {}, valSpan),
              el('td', {}, toggleBtn),
            ),
          );
        }
        eTbl.appendChild(eTb);
        envCard.appendChild(eTbl);
      }

      wrap.append(resCard, volCard, envCard);
      return wrap;
    }

    /* ==================== 分页 5：实时尾部日志与筛选 ==================== */
    function buildLogsPane() {
      const ct = detail.container || {};
      const tailSel = el('select', { cls: 'input-ctrl' },
        el('option', { value: '100', text: '最近 100 行' }),
        el('option', { value: '300', text: '最近 300 行' }),
        el('option', { value: '500', text: '最近 500 行（上限 64KiB）' }),
      );
      const filterInput = el('input', { cls: 'input-ctrl', placeholder: '输入关键词实时过滤日志行（如 error, panic）' });
      const autoChk = el('input', { type: 'checkbox' });
      const pre = el('pre', { cls: 'drawer-log-pre', text: '正在拉取日志…' });
      let rawLogCache = '';

      const applyFilter = () => {
        const kw = filterInput.value.trim().toLowerCase();
        if (!kw) {
          pre.textContent = rawLogCache || '(无日志输出)';
          return;
        }
        const matched = rawLogCache.split('\n').filter((ln) => ln.toLowerCase().includes(kw));
        pre.textContent = matched.join('\n') || `(未匹配到包含 "${filterInput.value}" 的日志行)`;
      };

      const fetchLogs = async () => {
        try {
          const res = await invoke('docker.container.logs', { id: ct.id, tail: Number(tailSel.value) });
          rawLogCache = res.logs || '';
          applyFilter();
        } catch (err) {
          pre.textContent = `日志拉取失败：${err?.message || '未知错误'}`;
        }
      };

      tailSel.addEventListener('change', () => void fetchLogs());
      filterInput.addEventListener('input', applyFilter);
      autoChk.addEventListener('change', () => {
        stopLogPoll();
        if (autoChk.checked) {
          logPollTimer = setInterval(() => void fetchLogs(), 3000);
        }
      });

      void fetchLogs();

      return el('div', { cls: 'sub-card' },
        el('div', { cls: 'form-inline' },
          tailSel,
          filterInput,
          el('label', { cls: 'chk-inline' }, autoChk, '每 3s 自动刷新'),
          el('button', { type: 'button', cls: 'btn ghost btn-sm', text: '手动刷新', on: { click: () => void fetchLogs() } }),
          el('button', {
            type: 'button',
            cls: 'btn ghost btn-sm',
            text: '复制当前日志',
            on: { click: () => void guardAction(() => hostCopy(pre.textContent || '', '已复制日志')) },
          }),
        ),
        pre,
      );
    }

    async function runOp(operation, payload, okMsg) {
      await guardAction(async () => {
        await invoke(operation, payload);
        await onListChanged();
        if (activeContainerId) {
          await loadContainerSettings(activeContainerId, activeTab, true);
        }
        showFeedback('ok', okMsg);
      });
    }

    return {
      open: loadContainerSettings,
      close: closeDrawer,
    };
  }

  let singletonWorkbench = null;
  window.createContainerSettingsWorkbench = createContainerSettingsWorkbench;
  window.QWQContainerDrawer = {
    init(deps) {
      singletonWorkbench = createContainerSettingsWorkbench(deps);
      return singletonWorkbench;
    },
    open(containerId, preferredTab = 'overview') {
      if (!singletonWorkbench) return Promise.resolve();
      return singletonWorkbench.open(containerId, preferredTab);
    },
    close() {
      singletonWorkbench?.close();
    },
  };
})();
