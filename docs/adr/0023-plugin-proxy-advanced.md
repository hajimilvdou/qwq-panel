# ADR-0023：高级代理插件 `proxy.advanced`

- 状态：Accepted（2026-11-13 用户批准 H1–H4 宿主配套与订阅 UUID 信任边界；硬限速方向已定；下行 ingress 回退与受整形用户上限待 spike S3/S4 后决定）
- 日期：2026-11-13（速率限制方向于 2026-11-13 经用户最终决定改为**首版硬限速**，覆盖此前软执行推荐）
- 关联：ADR-0002（placement/公开路由）、ADR-0004（AI 原生操作面）、ADR-0007（ABI 冻结）、ADR-0011（插件间调用）、ADR-0014（permission 命名）、ADR-0016（可达性审批）、ADR-0018（manifest 1.3 widgets，p2-b 轨道）、ADR-0019（Host Capability 服务 / qwq-capability helper，p6-cap 轨道）、ADR-0024（宿主公开 HTTP 端点，**已批准**）;core.xray `DESIGN.md`（只读参考，0022 预留，移植会话 ea69fdf2）;ARCH §5.4/§5.6/§9/§10.3/§13.1
- 编号：0023（0022 归 core.xray，0019–0021 归 P6，0024 归宿主公开端点）

## 0. 设计结论

1. `proxy.advanced` 是独立 `placement=node` 内置插件（`publisher.id=qwq-builtin`），在 core.xray 之上做**多用户、套餐、订阅、流量累计、配额与硬速率限制**。它**不碰 Xray 进程、不渲染原生配置、不读 Xray API、不直接执行 tc/nft**——核心动作经 `InvokePlugin` 调 core.xray，核心配置经宿主配置通路写入，流量整形经宿主 `system.traffic.shape` 能力（root helper）执行。
2. **速率限制（用户最终决定）：首版硬限速**，方案为**每用户 fwmark + tc HTB 整形**（不用 nft policing 丢包）。速率变更走 `tc class` 更新，**不重启 Xray**；用户增删仍走 core.xray Apply（首版全量切换）。**配额（软执行累计字节）保留，与硬限速并存**。
3. **硬限速依赖 core.xray Core Intent 扩展**：Xray 打 mark 需 routing `user→专属 direct outbound（sockopt.mark）`，要求 core.xray 增加可选 per-user mark 字段（仍 direct 出站，不开放任意上游）。该扩展由 core.xray 移植会话（ea69fdf2）同步加入;本 ADR §2.4 写清契约依赖，不擅自定其 schema。
4. **诚实边界（关键）**：mark 打在出站 socket 上，直接标记的是 **proxy↔上游**流量。上行（proxy→上游 egress）整形路径相对成熟;**下行（上游→proxy→client）ingress 整形是难点**，拟用 nft `socket mark` 取回 mark + ifb 重定向 + HTB egress，**可行性未验证**。REALITY 下 mark 传播、ingress 整形、1C1G HTB 规模**全部列为 spike 验证项**（§5.6，随 core.xray X6 或独立 spike 卡），**不得写成已支持**。spike 未过不得宣称对应方向硬限速已实现。
5. 流量累计是**reset epoch 感知的跨代次持久累计**（core.xray 首版只给原始计数器）。私有 DataDir SQLite 持久化。
6. 订阅经 ADR-0024（已批准）的公开端点 `/p/proxy.advanced/sub/{token}`，首版 VLESS 分享链接;token 鉴权在插件内，宿主剥离面板会话。
7. 本插件需要**四项宿主配套**（§3）：H1 持久 DataDir（复用 core.xray X2）、H2 跨插件配置读写能力服务、H3 受控后台只读调用授权（修订 ADR-0011 §2）、**H4 流量整形能力服务 `system.traffic.shape`（新 capability package + qwq-capability helper verb，CAP_NET_ADMIN 已在 ADR-0019 批准）**。H1–H4 待批准;不得绕过。
8. 首版诚实裁剪：支付/计费、多节点汇总、sing-box/Clash 输出格式、设备数硬绑定、在线连接数实时统计——列"不做"（§11）。**带宽硬限速已纳入首版**（不再是不做项），但下行整形以 spike 通过为前提。

## 1. 背景与定位

路线图第 6 项（HANDOFF §5）提前到首版部署前。core.xray（0022，只读参考）首版定"单核心、单入站、用户增删列、desired/running 双 revision、原始计数器 + reset epoch"，刻意不做多用户业务/套餐/订阅/跨代次累计/per-user 整形。`proxy.advanced` 补这一层（ARCH §9 业务插件 / 核心驱动分层）：

```text
浏览器 / AI / 订阅客户端
   │ 面板 operation（会话）          │ 公开订阅（token，无会话）
   ▼                                ▼
proxy.advanced（业务：用户/套餐/用量/订阅/速率策略）
   │ InvokePlugin（ADR-0011）   │ H2 pluginconfig   │ H4 system.traffic.shape
   ▼                            ▼                   ▼
core.xray（Intent/apply/observe，含 per-user mark 扩展）   qwq-capability helper（root，CAP_NET_ADMIN：tc/nft/ifb）
   │ 私有 Xray gRPC（StatsService）                        │ 宿主 netns
   ▼                                                      ▼
Xray 子进程（VLESS+REALITY+Vision+RAW/TCP，per-user direct outbound + sockopt.mark）
   │ 数据面（proxy↔上游 带 fwmark）
   ▼
上游 / 目标地址（HTB 按 mark 整形上行;ingress socket-mark+ifb 整形下行）
```

代理字节绝不经过 proxy.advanced，也不经过面板（ARCH §2.1）。整形作用在宿主内核数据面，不在插件进程。

### 1.1 已核实的宿主现状（设计依据）

| 事实 | 证据 | 约束 |
|---|---|---|
| InvokePlugin 无父调用拒绝（含定时器/read 父） | ADR-0011 §2;`plugin_invoke_test.go` "no parent" | 后台轮询 core.observe 需 H3 |
| 子调用 live 不拉起 | ADR-0011 §1;`plugin_runtime.go:1611` | core.xray 须常驻 |
| capability 到 operation 粒度，深度 ≤ 3，actor 继承父 | ADR-0011 §3/§4/§7 | 精确 capability 清单 |
| HostConfigService 只读、仅本插件 | `hostsvc/configservice.go` | 写 core.xray 配置需 H2 |
| RevealSecret 需派发 operation_id | `hostsvc/secrets.go:41` | 公开订阅/后台不能 reveal |
| ServePublicRoute 在冻结 ABI，宿主未实现 → ADR-0024 补 | `platform.proto:402–427` | 订阅依赖 ADR-0024（已批准） |
| hostsvc State 单值 1MiB/总量默认 4MiB | `hostsvc/config.go:158–163` | 关系型数据选 SQLite |
| 未知 capability 风险下限 medium;`system.*` high | `operations/action.go:240` | `system.traffic.shape` 落 high |
| qwq-capability helper 具 CAP_NET_ADMIN、宿主 netns、AF_NETLINK（ADR-0019，Proposed） | ADR-0019 决策 2 | H4 tc/nft 经此 helper，不新造 root 进程 |
| core.xray 首版单 direct 出站、users 无 mark、不导出公钥 | core.xray DESIGN §5/§13 | per-user mark 扩展（B-X4）与公钥导出（B-X1）均待 core.xray 轨道 |

## 2. 架构与调用契约

### 2.1 进程与放置

- `placement=node`、`lifecycle{startup:eager, background:true, update_strategy:restart, overlap_safe:false}`。采集/对账定时器 Activate 后启动、Deactivate 停止;两代不双跑后台。
- 与 core.xray 同节点，首版单实例 `default`。
- 默认沙箱（`PrivateNetwork=yes`、`AF_UNIX`、空 capability set），**不请求网络放宽**——本插件无数据面，整形由 root helper 在宿主 netns 执行，插件只经 host UDS 调能力。

### 2.2 对 core.xray 的 InvokePlugin 调用契约

经 `HostInvokeService.InvokePlugin`，`target=core.xray/default`、同节点;父为本插件 RUNNING write/job（H3 后台只读除外）。

| 目标 operation | effect | 场景 | capability |
|---|---|---|---|
| `core.xray/core.capabilities` | read | 对账支持矩阵（**含 per_user_mark 支持探测**） | `plugin.invoke:core.xray/core.capabilities` |
| `core.xray/core.status` | read | 读 desired/running revision、进程/API 状态 | `plugin.invoke:core.xray/core.status` |
| `core.xray/core.observe` | read | 读原始计数器（per-user up/down + reset_epoch） | `plugin.invoke:core.xray/core.observe` |
| `core.xray/core.validate` | read | 写配置后 apply 前无副作用校验 | `plugin.invoke:core.xray/core.validate` |
| `core.xray/core.apply` | write/job | 用户增删（含 mark/outbound 变更）全量切换 | `plugin.invoke:core.xray/core.apply` |

- `core.apply` 请求体遵循 core.xray DESIGN §7.1（`config_revision`/`expected_running_revision`）；冲突有界重试。子调用有效风险 = max(core.apply, 父)（ADR-0011 §5）；AI safe 模式用户变更进审批链。
- **速率变更不调 core.apply**：mark 不变、只改 tc class（H4 UpdateClass），Xray 不重启。仅用户增删/改 mark 才 core.apply。
- 深度 ≤ 3；幂等键 `plugin-invoke:proxy.advanced/default:<业务键>`。

### 2.3 自身不碰核心/内核的硬边界

- 不读 core.xray DataDir；不渲染 Xray 原生 JSON（只构造 Core Intent，`sdk/coreapi`）；不直连 Xray API、不启停进程。
- **不直接执行 tc/nft/ip**：插件无 CAP_NET_ADMIN、私有 netns，整形一律经 H4 能力 → root helper。
- 跨插件数据只经 InvokePlugin / H2 / H4，不读对方数据库（ARCH §5.6）。

### 2.4 core.xray per-user mark 扩展契约依赖（B-X4，待 core.xray 轨道）

硬限速要求 Xray 把每个用户的流量打到专属 fwmark。Xray 机制：routing 按 `user`（VLESS email）匹配 → 专属 outbound;该 outbound 为 `direct`（freedom）且 `sockopt.mark=<fwmark>`。据此向 core.xray 提出**契约依赖**（具体字段名/schema/版本由 core.xray 移植会话 ea69fdf2 定，本 ADR 不擅自固化）：

1. Core Intent `users[]` 增加**可选** per-user mark（uint32，限定保留 mark 段，§5.2）；缺省表示共享默认 direct 出站、不打 mark。
2. core.xray 渲染：每个带 mark 的用户 → 一个专属 direct outbound（`sockopt.mark`）+ 一条 routing 规则 `user: [qwq-user-<id>] → 该 outbound`。**仍仅 direct 出站，不开放任意上游**（mark 是 socket 标记，不是上游选择器）。
3. `core.capabilities` 须广告 `per_user_mark` 支持与否及可用 mark 段，供本插件探测;不支持时本插件硬限速不可用（`HARD_SHAPE_UNSUPPORTED`，诚实降级，§5.7）。
4. 契约版本按 core.xray 规则升级（其 DESIGN §5.1：核心专属能力用 `xray.<extension>` 命名空间并升契约版本）；本插件以探测到的能力为准，不假设字段已存在。
5. 统计标识不变（`user>>>qwq-user-<id>>>>traffic>>>…`）；mark 扩展不影响 observe 契约。

**未采用**：让 proxy.advanced 自行渲染 Xray outbound/routing（破坏分层、碰原生配置）；用 nft 按 UUID 限速（L3/L4 看不到 UUID，不可行）。

## 3. 宿主最小配套设计（H1–H4 待批准）

四项都不改冻结 ABI、不改 manifest schema（capability name/scope 模式已容纳）。H2/H4 复用 ADR-0019 能力传输与能力门;H3 是宿主调用策略修订。

### 3.1 H1：持久 DataDir（复用 core.xray X2）

- `/var/lib/qwq-plugin-data/proxy.advanced/default/proxy.db`（与 `internal/sandbox/paths.go` 一致），经 `InitializeRequest.data_dir` 下发，`StateDirectory=` 赋动态 UID；`state.backup_paths=["state/"]` 非空信号。
- 启动校验绝对路径/无 symlink 逃逸/仅当前 UID 可写/≤0700；失败不启动（`DATA_DIR_UNAVAILABLE`）。复用 X2，不重复造。

### 3.2 H2：跨插件配置读写能力服务 `qwq.capability.pluginconfig.v1`

- 缺口：HostConfigService 只读且仅本插件;写 core.xray desired（用户/mark 增删）无通路。
- 形态（ADR-0019 决策 1/4，零 ABI 改）：`api/qwq/capability/pluginconfig/v1/`，挂 host UDS，经 `prepareCall` + 能力门；forwarder agent/controller 本地（复用 `putPluginConfig` 管线），不经 root helper。

| RPC | 请求 | 返回 | effect/风险 | capability |
|---|---|---|---|---|
| `GetConfig` | `{target_plugin_id}` | `{config_json(redacted), revision}` | read/low | `config.read:<target>` |
| `PutConfig` | `{target_plugin_id, config_json, expected_revision}` | `{revision}` | write/medium | `config.write:<target>` |

- 能力门：scope 精确匹配 target；PutConfig 需派发 operation_id + operation 级 capability；secret 提取 owner=`plugins/<target>`、purpose=`plugin.config`;已是 `{"$secret":…}` 引用原样保留；目标 schema 校验 + ValidateConfig + revision 乐观并发；审计脱敏；PutConfig 限频 ≤12/min。
- **私钥/既有 UUID/mark 无关秘密经 ref 透传，明文不经过本插件**;仅本插件新生成 UUID 以明文写入（订阅用），宿主提取为 core.xray ref。
- 未采用：core.xray 加 users.replace operation（破坏分层）；插件走公共 API+service token（回环 egress 默认拒）；扩 HostConfigService（改 ABI）。

### 3.3 H3：受控后台只读调用授权（修订 ADR-0011 §2）

- 缺口：后台采集定时器无父 → 现状无法调 core.observe。
- 新 capability `plugin.invoke.background:<plugin_id>/<operation>`；Invoker 无父策略**仅当**：调用方持 `plugin.invoke:<t>/<op>` + `plugin.invoke.background:<t>/<op>`、目标目录 `effect==read`、目标 live、限频 ≤12/min、deadline ≤10s 时放行；write/destructive 无父仍拒；审计 `plugin.invoke`（`background:true`、`invoked_by`）;read 不落 operation 记录；无 actor 继承（授权边界=安装时批准的 capability）。
- 注：**能力服务的读 RPC（如 H4 GetShape）不需 operation_id**（ADR-0019 决策 4），后台可直接调，不走 H3；H3 只解决 InvokePlugin（core.xray observe）的无父问题。
- 未采用：外部 cron+service token（采集停则配额静默失效、撑大 operations 表）作主路径；core.xray 推送统计事件（改其契约、journal 压力）。

### 3.4 H4：流量整形能力服务 `qwq.capability.traffic.v1`（新）

- 缺口：插件无 CAP_NET_ADMIN/宿主 netns，无法 tc/nft/ifb。ADR-0019 的 qwq-capability helper 已具 CAP_NET_ADMIN、宿主 netns、AF_NETLINK（**已批准**），但无整形 verb。
- 形态：新 capability package `qwq.capability.traffic.v1.TrafficService`（ADR-0019 布局，不进 ABI）；capability `system.traffic.shape`（scope `self`=本节点 qwq 自有整形对象）；forwarder 经 `capability.sock` 路由到 qwq-capability helper 新 verb。`system.*` → 风险下限 high（`action.go:246`）。

| RPC | 请求 | 返回 | effect/风险 |
|---|---|---|---|
| `GetShape` | `{}` | `{qdiscs[], classes[{mark,classid,rate,ceil}], ifb[], revision}` | read/low |
| `ApplyShape` | `{iface, ifb, classes[{mark,classid,rate_mbps,ceil_mbps}], expected_revision}` | `{revision}` | write/high，reachability |
| `UpdateClass` | `{mark, rate_mbps, ceil_mbps, expected_revision}` | `{revision}` | write/high，reachability（`tc class change`，不重启 Xray） |
| `RemoveClass` | `{mark, expected_revision}` | `{revision}` | write/high，reachability |
| `ResetShape` | `{expected_revision}` | `{revision}` | destructive/high，reachability |

- helper verb（白名单，固定二进制+参数 schema，无通用 exec）：`traffic.get`（`tc qdisc/class show` + `ip link show ifb` 解析）、`traffic.apply`（`ip link add ifb…`、`tc qdisc add … htb`、`tc class add`、`tc filter add … fwmark`、nft `inet qwq` 专用 ingress 链 `meta mark set socket mark` + clsact redirect）、`traffic.update-class`（`tc class change`）、`traffic.remove-class`（`tc class/filter del`）、`traffic.reset`（`tc qdisc del` + `ip link del ifb` + nft 链清空）。
- **宿主事实注入与防自锁**：forwarder 注入保留 mark 段（仅 proxy 用户段）、默认类（未标记流量=面板/SSH，高优先/不限速）、管理 iface 白名单;helper 再校验。**面板/SSH 流量不带 proxy mark，落入默认类，不被整形**——这是防自锁不变量，spike 必须验证（§5.6 S5）。
- 能力门：写需派发 operation_id + operation 级 `system.traffic.shape`;读只需 capability；scope=self；写令牌桶限频；审计不含秘密。
- nft 归属：整形 ingress 链在 `inet qwq` 表内**专用链**，与 firewall 能力（ADR-0019/0021）的链分离，互不覆盖;若 firewall 未接管，traffic 链独立可用。
- 1C1G：HTB 类规模上限与内核内存见 §12；helper 一请求一激活，无常驻 root 进程。

## 4. 多用户与套餐

### 4.1 数据模型（私有 SQLite，§6）

```text
plan(id, name, quota_bytes, rate_limit_mbps, duration_days, max_devices, enabled, revision, …)
user(id, plan_id, display_name, uuid, mark, status, token_hash, token_salt,
     expires_at, suspended_reason, core_synced_revision, shape_synced_revision, revision, …)
usage(user_id, epoch, base_up, base_down, acc_up, acc_down, last_seen, …)
usage_total(user_id, lifetime_up, lifetime_down, period_up, period_down, period_start, …)
```

- `user.id` 稳定面板 ID（`^[a-z][a-z0-9._-]{0,31}$`），映射 core.xray `users[].id`;不用 email/标签作主键。
- `uuid` 本插件生成（明文私有 SQLite，订阅用）；写 core.xray 时 H2 提取为 ref。
- **`mark`**：本插件分配的 per-user fwmark（保留段内唯一，§5.2），写入 core.xray Intent `users[].mark`（B-X4）与 H4 tc class。
- `status`：`active|suspended|deleted`;`suspended_reason`：`manual|quota|expired`。
- **`quota_bytes`（软执行累计字节）与 `rate_limit_mbps`（硬执行 HTB 速率）并存**：`quota_bytes=0` 无限;`rate_limit_mbps=0` 不限速（该用户不建 HTB 类，仅配额）。`max_devices` 首版仅元数据。
- 用户上限 256（core.xray users 硬上限）；**受整形用户上限**另受 HTB 规模约束（§12，spike 测定）。

### 4.2 用户生命周期（核心 + 整形协同）

| 动作 | operation | 核心副作用 | 整形副作用（H4） |
|---|---|---|---|
| 创建 | `proxy.user.create` | 生成 UUID/mark → H2 PutConfig（含 mark）→ core.apply | AddClass（mark→HTB 类，rate=套餐） |
| 改套餐/有效期 | `proxy.user.update` | 改 SQLite;必要时 core.apply | 若 rate 变 → UpdateClass（不重启 Xray） |
| 停用 | `proxy.user.suspend` | 移出 Intent users → core.apply | RemoveClass |
| 恢复 | `proxy.user.resume` | 重新加入 → core.apply | AddClass |
| 删除 | `proxy.user.delete` | 移出 → core.apply → 删 SQLite | RemoveClass |
| 过期/超额 | 后台对账 | 按 suspend 路径 | RemoveClass |
| 套餐速率变更 | `proxy.plan.set` | 改 SQLite | 对该套餐每个 active 用户 UpdateClass（批量，不重启 Xray） |

- **协同顺序**：加用户先 AddClass 再 core.apply（流量起即受整形）;删用户先 core.apply（停 mark）再 RemoveClass。失败标 `shape_synced_revision`/`core_synced_revision` 待对账，后台/`proxy.shape.reconcile` 修复;不允许"核心已删但 tc 类残留"或"mark 已打但无类"的静默偏差。
- 单一写入通路（ADR-0004 D1）；revision 乐观并发;ResourceChange 上报。

### 4.3 配额状态机（软执行，保留）

```text
active ──(period_usage ≥ quota_bytes 且 quota>0)──▶ suspending(quota)
active ──(expires_at < now)──────────────────────▶ suspending(expired)
suspending ──(core.apply + RemoveClass 成功)─────▶ suspended
suspending ──(失败, 有界重试)────────────────────▶ suspend_failed ──(重试/告警)
suspended ──(resume / 续费重置 period)───────────▶ active
```

- 配额按周期用量判定;超额停用有 ≤1 采集周期窗口（软执行固有代价，UI 明示）。**硬限速（HTB）始终在线**，与配额软执行互补：HTB 限瞬时带宽，配额限累计字节。

### 4.4 采集触发（主路径 + 降级）

- 主路径（H3）：Activate 后定时器默认 60s（可配 30–300s），H3 无父调 core.observe；顺带 H4 GetShape（能力读，无需 operation_id）对账整形状态。
- 降级（无 H3）：`proxy.usage.collect`（write/job）由人/AI/外部 cron 触发；自动配额不可用，UI 明示。

### 4.5 速率与配额并存语义

- `rate_limit_mbps>0`：HTB 类常驻（active 期间），瞬时带宽硬上限；`quota_bytes>0`：累计字节软上限，超额停用。两者独立判定、可同时生效。
- 速率变更（plan.set / user.update）→ H4 UpdateClass（`tc class change`），**Xray 不重启、mark 不变**；仅用户增删/改 mark 触发 core.apply 全量切换。

## 5. 硬速率限制设计（per-user fwmark + tc HTB）

### 5.1 方案与数据面

- 每用户分配唯一 fwmark；core.xray 经 per-user direct outbound `sockopt.mark` 打 mark（B-X4）;tc HTB 按 fwmark 分类整形。**不用 nft policing 丢包**（用户指定，HTB 整形而非丢包）。
- 整形作用在 **proxy↔上游**这条腿（mark 所在）：限住这条腿即限住用户吞吐（proxy 转发不能快于其上游收发）。client↔proxy 腿不直接整形，但被上游腿约束。
- 上行（用户→上游）：proxy→上游 egress 带 mark → 物理 iface egress HTB 按 mark 分类。
- 下行（上游→用户）：上游→proxy ingress 属带 mark 的 socket → 取回 mark + ifb 重定向 + ifb egress HTB（§5.4，**难点，spike  gated**）。

### 5.2 mark 分配与隔离

- 保留段（暂定 `0x5100–0x51FF`，256 个，spike 确认与宿主无冲突后固化）；本插件在段内为每用户分配唯一 mark，存 user.mark。
- helper 校验 mark 仅在保留段;面板/SSH/系统流量**不带此段 mark**，落 HTB 默认类（高优先/不限速）→ 防自锁不变量。
- mark 与 core.xray Intent `users[].mark`、tc class、nft 规则三方一致，由对账保证。

### 5.3 上行整形（egress，相对成熟，仍 spike 确认）

- 物理 iface（管理 iface 白名单内，默认路由 iface）root qdisc `htb default <未标记类>`;每用户 class（rate=ceil=`rate_limit_mbps`）;filter `fwmark <mark> flowid <classid>`。
- 速率变更 `tc class change dev <iface> classid <id> rate <r> ceil <r>`，不重启 Xray、不重建 qdisc。
- spike S2 验证：sockopt.mark 在锁定 Xray 版本 + REALITY/Vision/RAW 下正确打到 proxy→上游 egress;HTB 按 mark 限速生效。

### 5.4 下行整形（ingress，难点，spike gated，不得宣称已支持）

**拟用路径**（待验证）：
1. nft `inet qwq` 专用 ingress 链：`meta mark set socket mark`（按 packet 所属本地 socket 取回 SO_MARK，即 proxy↔上游 socket 的 per-user mark）。
2. 物理 iface clsact ingress：`tc filter … action mirred egress redirect dev ifb0`（把上游→proxy 流量重定向到 ifb）。
3. ifb0 egress HTB：按取回的 mark 分类整形（与上行同 mark→同速率）。
4. 整形后回栈 → proxy 读取 → 转发 client。

**必须 spike 验证的不确定点（S3）**：
- nft `socket mark` 表达式在锁定 nftables 版本可用，且 ingress 阶段 socket 查找能命中正确的 proxy↔上游 socket（TCP established）。
- **netfilter ingress hook 与 tc clsact ingress 的执行顺序**：mark 必须在 mirred redirect 之前设置，否则 ifb 上无 mark 可分类。此顺序是成败关键，未验证。
- ifb 重定向后 mark 保留、HTB 生效、回栈正常;REALITY/Vision 内层流量是否影响 socket 查找。
- 备选（若 socket-mark+ifb 不可行）：其他经 spike 验证可行路径;**无可行路径则下行硬限速首版不可交付**，回退由用户决定（§5.7），不得宣称下行已硬限速。

### 5.5 tc/nft 管理经 helper

- 全部 tc/nft/ip 由 H4 → qwq-capability helper（CAP_NET_ADMIN，宿主 netns）执行;插件不碰内核。
- 幂等：ApplyShape/UpdateClass 带 expected_revision;helper 先 `tc … show` 判存在再 add/change，重复调用幂等。
- 持久化：整形规则重启后由本插件 Activate 对账重建（HTB/ifb/nft 非持久，重启丢失）;对账以 SQLite 期望态为准。

### 5.6 spike 验证项（随 core.xray X6 或独立 spike 卡 PA-S1，不得写成已支持）

| # | 验证项 | 通过判据 |
|---|---|---|
| S1 | REALITY+Vision+RAW 下 routing user→专属 direct outbound + sockopt.mark 正确打 mark | 抓包/`ss -e` 确认 proxy↔上游 socket 带预期 mark |
| S2 | 上行 egress HTB 按 mark 限速 | iperf3 经代理，上行带宽钳制在设定值 ±误差 |
| S3 | **下行 ingress：nft socket mark 取回 + clsact/ifb 重定向 + HTB egress**（含 hook 顺序、mark 保留） | 下行带宽钳制;面板/SSH 不受影响 |
| S4 | 1C1G 下 HTB 类规模（至 256）CPU/内存/吞吐/延迟 | 测得规模上限与开销，定 §12 预算 |
| S5 | mark 段与宿主现有 mark 隔离;面板/SSH 落默认类不被整形 | 管理通道吞吐/延迟无退化 |
| S6 | tc class change 速率热变更不重启 Xray、不丢连接 | 变更期间连接保持、速率生效 |

证据含锁定版本、配置、命令、输出摘要、测试位置;任何失败回 ADR，不擅自扩权/扩协议。**S3 未过 → 下行硬限速不可宣称;S1/S2 未过 → 硬限速整体不可交付。**

### 5.7 诚实降级与回退

- core.xray 未广告 per_user_mark（B-X4 未就绪）→ `HARD_SHAPE_UNSUPPORTED`，硬限速不可用；UI 明示，仅配额软执行。
- S1/S2 未过 → 硬限速整体阻塞，不交付假硬限速。
- S3 未过（下行不可行）→ 上行硬限速 + 下行配额软执行（明确告知用户下行非硬限速），或整体回退配额软执行——**由用户决定**，不擅自宣称双向硬限速。
- 受整形用户超 HTB 规模上限 → 拒绝新建/超限部分仅配额（`SHAPE_LIMIT_REACHED`），UI 明示。

## 6. 状态存储选型：DataDir SQLite（选定）

- 关系型用户/套餐/用量/token/mark，需索引/事务/范围查询;每 60s 批量写;256 用户远超 KV 配额（单值 1MiB/总量 4MiB）→ SQLite。State KV 仅游标/配置（`kv_max_kb=64`）。
- `<DataDir>/state/proxy.db` 0600 + 目录 0700；WAL + 事务原子；state schema v1 独立迁移/回滚。
- **信任边界**：SQLite 含 UUID 明文（订阅渲染必需，公开请求不能 reveal）——与 core.xray 运行快照同信任级（单 UID/0700/0600）；`backup_paths=["state/"]` 备份含 UUID 明文，须同等保护。token 只存 SHA-256；mark 非秘密。
- 体量：256 用户 ×（user~220B + usage~120B×代次 + total~100B）< 1MiB；`disk_max_mb=32` 软限制。

## 7. 订阅

- 公开端点（ADR-0024 已批准）：`GET /p/proxy.advanced/sub/{token}`，route `sub`，capability `public.route:sub`。
- token 32B 随机 base64url;SQLite 存 SHA-256→user;active 才返回;轮换/撤销即时失效。token 经 **read** op `proxy.subscription.get` 返回（read 不落 operations 表）；write 结果不含 token。
- 首版 VLESS 分享链接（`vless://<uuid>@<host>:<port>?security=reality&encryption=none&flow=xtls-rprx-vision&type=tcp&sni=<sni>&pbk=<pk>&sid=<sid>&fp=<fp>#<name>`），text/plain。
- 素材：uuid 自 SQLite;host=config.public_host;port/sni/sid 自 H2 GetConfig;**pbk 依赖 B-X1**（core.xray 导出公钥，未就绪 config 手工填）;fp 默认 chrome。
- suspended 403、无效 token 404;宿主剥离会话头、审计不记 path;no-store。其他格式列后续。

## 8. UI（manifest 1.3）

- 通用配置/operation 页 + `ui/` 沙箱 iframe 管理页（用户/套餐 CRUD、订阅链接复制、速率/配额展示）。
- `ui.routes`：`/proxy`（nav，permission `proxy.advanced:read`）。
- widgets（read/invoke/空 payload，refresh≥2s）：`users`(stat)、`traffic`(stat 周期用量)、`trend`(series)、**`shape`(stat 受整形用户数/限速状态)**。形状与 p2-b/Shell 对齐（待确认）。
- 明示：速率硬限速生效状态、配额软执行窗口、下行整形若 spike 未过的降级提示。插件字符串不可信文本渲染。

## 9. Operation 表

permission 资源段 `proxy.advanced`（ADR-0014）。**声明 `system.traffic.shape` 的写操作风险下限 high（system.*）且 `reachability=true`**（保守：tc 误配可能影响管理通道，spike 确认隔离后可复议;manifest 声明触发 ADR-0016 R1 钳制 approval≥ai_confirm、risk≥high）。声明 `plugin.invoke`/`config.write` 落 medium。纯本地 read 落 low。

| Operation | mode | effect | risk | approval | reachability | permission | 关键 capabilities |
|---|---|---|---|---|---|---|---|
| `proxy.plan.list` | invoke | read | low | auto | false | `:read` | — |
| `proxy.plan.set` | invoke | write | high | confirm | true | `:write` | system.traffic.shape, state.kv.write（速率变更触 tc） |
| `proxy.plan.delete` | invoke | write | medium | ai_confirm | false | `:write` | state.kv.write（无用户引用才可删，不触 tc） |
| `proxy.user.list` | invoke | read | low | auto | false | `:read` | —（脱敏） |
| `proxy.user.get` | invoke | read | low | auto | false | `:read` | —（脱敏） |
| `proxy.user.create` | job | write | high | confirm | true | `:write` | system.traffic.shape, config.read/write:core.xray, plugin.invoke:core.xray/core.apply |
| `proxy.user.update` | invoke | write | high | confirm | true | `:write` | system.traffic.shape, config.write:core.xray, plugin.invoke:core.xray/core.apply |
| `proxy.user.suspend` | invoke | write | high | confirm | true | `:write` | system.traffic.shape, config.write:core.xray, plugin.invoke:core.xray/core.apply |
| `proxy.user.resume` | invoke | write | high | confirm | true | `:write` | system.traffic.shape, config.read/write:core.xray, plugin.invoke:core.xray/core.apply |
| `proxy.user.delete` | invoke | destructive | high | confirm | true | `:write` | system.traffic.shape, config.write:core.xray, plugin.invoke:core.xray/core.apply |
| `proxy.usage.get` | invoke | read | low | auto | false | `:read` | —（本地累计） |
| `proxy.usage.collect` | job | write | medium | ai_confirm | false | `:write` | plugin.invoke:core.xray/core.observe |
| `proxy.shape.get` | invoke | read | low | auto | false | `:read` | —（本地缓存整形态） |
| `proxy.shape.reconcile` | job | write | high | confirm | true | `:write` | system.traffic.shape, config.read:core.xray, plugin.invoke:core.xray/core.apply |
| `proxy.subscription.get` | invoke | read | low | auto | false | `:read` | —（返回 URL，read 不落库） |
| `proxy.subscription.rotate` | invoke | write | medium | ai_confirm | false | `:write` | state.kv.write |
| `proxy.status` | invoke | read | low | auto | false | `:read` | —（本地缓存） |
| `proxy.widget.{users,traffic,trend,shape}` | invoke | read | low | auto | false | `:read` | —（空 payload） |

- 插件级 capabilities 汇总：`state.kv.read/write:self`、`config.read/write:core.xray`、`plugin.invoke:core.xray/{capabilities,status,observe,validate,apply}`、`plugin.invoke.background:core.xray/core.observe`、**`system.traffic.shape:self`**、`public.route:sub`、`events.publish:proxy.advanced`。**不声明** secret.reveal / network.*。
- 后台对账调 H4 GetShape（能力读，无需 operation_id）;整形写（ApplyShape/UpdateClass/RemoveClass）只在上述 write operation 内（需派发 operation_id）。
- 审批卡显示用户增删/速率变更/是否重启核心，**不显示 UUID/私钥/token**。

## 10. 错误码与边界依赖

### 10.1 错误码

| 码 | 用途 |
|---|---|
| `VALIDATION_FAILED` | 参数/schema/语义失败 |
| `USER_NOT_FOUND`/`PLAN_NOT_FOUND`/`USER_EXISTS`/`USER_LIMIT_REACHED`/`PLAN_IN_USE` | 资源/约束 |
| `REVISION_CONFLICT`/`PRECONDITION_FAILED` | 乐观并发/前置 |
| `CORE_UNAVAILABLE`/`CORE_APPLY_FAILED`/`CONFIG_SYNC_FAILED` | 核心/配置 |
| `HARD_SHAPE_UNSUPPORTED` | core.xray 未广告 per_user_mark（B-X4 未就绪） |
| `SHAPE_UNAVAILABLE`/`SHAPE_APPLY_FAILED`/`SHAPE_SYNC_FAILED` | H4 不可用/tc 失败/对账失败 |
| `SHAPE_LIMIT_REACHED` | 超 HTB 规模上限 |
| `SHAPE_MARK_CONFLICT` | mark 段冲突/越界 |
| `SUBSCRIPTION_INVALID`/`DATA_DIR_UNAVAILABLE`/`INTERNAL` | 订阅/目录/其余 |

### 10.2 边界登记（core.xray / P6 / p2-b）

- **B-X1**：core.xray 导出 REALITY 公钥 + short_ids（订阅 pbk；未就绪手工填）。
- **B-X4（新，硬限速关键）**：core.xray Core Intent per-user mark 扩展（§2.4）+ capabilities 广告；移植会话 ea69fdf2 同步加入;本插件探测能力，未就绪硬限速降级。
- **B-X2**：core.xray 移植版 `.cache/wt/core-xray` 截至本会话仅 PLAN/SPIKE-PLAN/SUPPLY-CHAIN（DESIGN 未移植，进行中）；以源 DESIGN 为准，operation/mark 契约待 X4–X9 复核。
- **B-X3**：复用 X2 DataDir、依赖 X9 epoch、联调排 X11 后；**spike S1–S6 随 X6 或独立 PA-S1**。
- **B-P6**：H2/H4 复用 ADR-0019 传输/能力门/qwq-capability helper（p6-cap）；H2/H3/H4/ADR-0024 宿主实现与 p6-cap **串行**。H4 新 verb 扩 helper 白名单（CAP_NET_ADMIN 已批准，新 verb 待批准）。
- **B-P2B**：widgets 形状对齐 p2-b 步骤 10；`system.traffic` 是否补入 `ReachabilityCapabilityPrefixes`（R2）为可选跨轨道项——本 ADR 以 manifest `reachability=true` 声明触发 R1，不依赖 R2 改清单。

## 11. 首版明确不做

支付/计费、多节点用量汇总、sing-box/Clash/JSON 订阅格式、设备数硬绑定、在线连接数/实时在线用户统计、用户自助注册门户、邮件告警。**带宽硬限速已纳入首版**（§5），但下行整形以 spike S3 通过为前提;若 S3 未过按 §5.7 回退（用户决定）。

## 12. 1C1G 资源预算

- manifest resources：`memory_max_mb=32`（GOMEMLIMIT≈26MiB）、`cpu_quota_percent=5`、`pids_max=8`、`fds_max=64`、`disk_max_mb=32`、`kv_max_kb=64`。
- 采集：60s 一次 core.observe（≤256×2 计数器，单 RPC<100KB）+ H4 GetShape；SQLite 每周期批量事务写。
- **HTB 规模（spike S4 测定，暂定上限）**：每受整形用户上行+下行各 1 类（ifb 与物理 iface），256 用户 → 至多 512 类。HTB 多类在 1 vCPU 有 CPU/内存开销，**首版受整形用户上限暂定 ≤128（待 S4 实测调整）**，超限 `SHAPE_LIMIT_REACHED`;内核 qdisc 内存不计入插件 RSS 但纳入节点预算，S4 给出每类开销与上限。
- helper 一请求一激活（ADR-0019），无常驻 root；tc class change 热变更开销低。
- 订阅低频，宿主 per-IP 限流 + 每插件在途 ≤8（ADR-0024）。

## 13. 测试清单

**构建机单测（fake，不碰真实系统）**：
- fake core.xray：observe 序列（epoch 切换/回绕/重启清零）、capabilities（per_user_mark 支持/不支持）、apply 冲突;配额状态机、跨代次累计、对账。
- fake pluginconfig：Intent 构造（私钥/既有 UUID ref 透传、新 UUID 明文、**mark 字段**）、revision 冲突、owner 绑定。
- fake traffic 能力：ApplyShape/UpdateClass/RemoveClass 幂等、mark 段校验、默认类保护、规模上限、revision、能力门（写需 operation_id）。
- fake HostInvoke：capability 缺失/无父 write 拒绝/H3 无父 read 放行限频/深度/幂等前缀。
- 协同：用户增删的核心+整形顺序与失败对账;速率热变更不触发 core.apply。
- 订阅：token 哈希/轮换/撤销/403/404/VLESS 渲染/read 不落库。
- SQLite/manifest/脱敏夹具（响应/事件/审计不含 UUID/私钥/token；订阅端点响应除外）。

**netns 集成（构建机独立 network namespace，不碰测试机真实网络）**：
- `ip netns` 内 HTB qdisc/class/filter（fwmark 分类）、ifb 重定向、nft `socket mark` 链、默认类保护;`tc class change` 热变更;规模/开销测量（S4 可在 netns 初测，真实 1C1G 复核测试机）。

**spike（PA-S1，随 core.xray X6 或独立；测试机届时先经用户确认）**：S1–S6（§5.6），真实 Xray+REALITY 客户端、iperf3 上下行限速、hook 顺序、mark 隔离、1C1G 规模。**spike 未过不得宣称对应硬限速已支持。**

**真实联调（测试机，core.xray X11 后，届时确认）**：建用户→订阅→真实客户端→上下行硬限速验证→流量累计→超额停用→恢复；H2/H3/H4/ADR-0024 真实链路;1C1G 报告。

## 14. 已批准项（2026-11-13 用户批准；ingress 回退/规模上限待 spike）

1. **H2 pluginconfig 能力服务**（`config.read/write:<plugin_id>`）。
2. **H3 后台只读调用授权**（修订 ADR-0011 §2）。
3. **H4 流量整形能力服务**（`system.traffic.shape`，新 capability package + qwq-capability helper 新 verb；CAP_NET_ADMIN 已批准，新 verb/沙箱细节待批准）。
4. **H1 DataDir 复用**（core.xray X2）。
5. **硬限速方向已用户决定**（首版硬限速，per-user fwmark+HTB）；**下行 ingress 整形以 spike S3 通过为前提**，S3 未过的回退方案需用户届时决定（§5.7）。
6. **B-X4 core.xray per-user mark 扩展**契约依赖（ea69fdf2 协调）；B-X1 公钥导出。
7. **订阅 UUID 明文信任边界**；widgets 形状对齐。
8. **受整形用户上限与 HTB 预算**（暂定 ≤128，spike S4 实测调整）。

## 15. 代价

- 四项宿主配套（H2/H3/H4 + H1 复用）+ core.xray mark 扩展（B-X4）+ spike，显著增加实现/审查/跨轨道协调面。
- **下行 ingress 整形（socket mark+ifb+hook 顺序）是未验证难点**，可能 spike 失败导致下行硬限速首版不可交付；诚实降级路径已定（§5.7），不宣称未验证能力。
- HTB 多类在 1C1G 有 CPU/内存/吞吐开销，规模上限需实测；整形误配有影响管理通道风险（默认类保护 + reachability 审批 + spike S5 收敛）。
- 用户增删需核心 apply + tc 协同，失败对账复杂;速率热变更不重启 Xray 是收益。
- UUID 明文落私有 SQLite/备份，信任边界同 core.xray 运行快照。
