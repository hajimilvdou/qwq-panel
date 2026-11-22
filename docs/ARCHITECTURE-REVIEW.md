# 架构审查：问题与改进建议

> 日期：2026-11-01  
> 审查对象：`ARCHITECTURE.md`、`HANDOFF.md`、`0001-architecture-baseline.md`、`platform_v1.proto`、`manifest.schema.json`  
> 视角：全栈工程、服务器运维、网络安全、性能优化  
> 原则：不改变 ADR-0001 的 18 项决策，也不改变"宿主稳定、业务全插件、1C1G 可用、默认不信任第三方"的理念；只补缺口、消除矛盾，把"做什么"落到"怎么做"。

> **落实状态（v1.1）**：P0 全部（C1–C11）及 F1、D1–D8 已合入 `ARCHITECTURE.md` v1.1、ADR-0002/0003/0004 与重写后的 proto、manifest schema；P1/P2 项已写入架构正文对应章节，并在 `IMPLEMENTATION-PLAN.md` 中排期。逐项对照见 §9。  
> **行号说明**：本文引用的行号（如 `platform_v1.proto:19-26`）指向 `archive/v1-baseline/` 中的原始文件。  
> **命名说明**：§0–§8 是对 v1 的审查记录，保留当时的占位前缀 `panel`（`panel-agent`、`/var/lib/panel` 等）；现行名称见 ADR-0005 的映射表，§9 已使用现行名称。

## 0. 结论

整体方向正确。三层边界、Agent 主动连接、宿主资源所有权、配置 revision、事务式卸载、事件分级背压，这些是同类面板普遍缺失、而本设计已经想清楚的部分。问题集中在三类：

1. **契约层缺口（P0）**：proto 和 manifest 还没表达出架构正文已经决定的行为，例如同进程多实例、跨插件调用、字段级配置错误、启动策略、SBOM。这些必须在 ABI 冻结前补上，冻结后再改就是破坏性变更。
2. **安全的"怎么做"未定义（P1）**：非 root 的 Agent 如何以独立 UID 拉起沙箱插件；go-plugin 的 AutoMTLS/SecureConfig 与 Reattach 互斥；首次 enroll 如何确认 Controller 身份；iframe 沙箱的关键细则。这些不定，P2/P4 实现时会各自发挥。
3. **1C1G 下的运维细节（P1–P2）**：GOMEMLIMIT、OOM 优先级、SQLite 写事务模式与 WAL 检查点、日志洪泛、虚拟化环境探测。不处理不会立刻出错，但会在小内存机器上以 OOM、`SQLITE_BUSY` 或日志占满磁盘的形式出现。

除两份需要新增的 ADR（插件放置位置、插件拉起路径）外，所有建议都在现有决策范围内。

**优先级口径**：P0 = ABI/manifest 冻结前必须改，否则后续是破坏性变更；P1 = 对应阶段实现前必须定，影响安全或正确性；P2 = 实现时落实的工程细节；P3 = 文档一致性。

## 1. 问题总表

| 编号 | 级别 | 视角 | 问题 |
|---|---|---|---|
| C1 | P0 | 全栈 | ABI 无法表达"同进程多实例"，插件放置位置未定义 |
| C2 | P0 | 安全 | Host Service 的调用者身份取自插件自报字段 |
| C3 | P0 | 全栈 | 没有宿主中介的跨插件调用，Core Intent 无法落地 |
| C4 | P0 | 正确性 | 蓝绿期间后台任务会双跑，缺少激活阶段 |
| C5 | P0 | 安全 | manifest 签名位置矛盾，内嵌签名有解析歧义 |
| C6 | P0 | 安全 | manifest 路径字段可路径穿越（已用 schema 自身正则验证） |
| C7 | P0 | 全栈 | manifest 缺少 §5.3 要求的字段，且没有演进机制 |
| C8 | P0 | 全栈 | 配置校验没有字段级错误结构 |
| C9 | P0 | 正确性 | 事件发布可伪造宿主字段，可靠订阅没有 ack |
| C10 | P0 | 工程 | proto 过不了 Buf 默认 lint，命名会固化进 wire |
| C11 | P0 | 安全 | Secret 明文返回，缺少绑定与审计约束 |
| S1 | P1 | 安全/运维 | 插件拉起路径与 Agent 权限矛盾；go-plugin 的限制未纳入设计 |
| S2 | P1 | 安全 | 缺少可执行的默认沙箱模板与验收门槛 |
| S3 | P1 | 安全 | 把 loopback 当信任边界（pprof、Xray API） |
| S4 | P1 | 安全 | 首次 enroll 没有固定 Controller 身份，可被中间人接管节点 |
| S5 | P1 | 安全 | Controller 失陷即全部节点 root 失陷，节点侧没有兜底 |
| S6 | P1 | 安全 | 节点/插件上报内容未按不可信处理，存在存储型 XSS 入口 |
| S7 | P1 | 安全 | sandbox iframe 缺少几条关键细则 |
| S8 | P1 | 安全 | 管理入口缺少首次初始化、TLS、MFA、防锁死的设计 |
| S9 | P1 | 安全 | 供应链：索引防回滚、解包实现、远程 `$ref` |
| S10 | P1 | 安全/性能 | 插件可借审计/日志洪泛对宿主施压 |
| O1 | P1 | 运维 | 支持矩阵缺少虚拟化类型和 cgroup 版本 |
| O2 | P1 | 运维/性能 | 1G 内存保护缺少 GOMEMLIMIT、MemoryHigh、OOM 优先级 |
| O3 | P2 | 性能 | SQLite 写入纪律与插件 KV 存放位置 |
| O4 | P2 | 运维 | 目录布局、宿主发布/回滚与安装器 |
| O5 | P2 | 运维 | 日志洪泛、健康端点、诊断包、磁盘配额实现 |
| O6 | P2 | 性能 | 探针形态的真实内存成本需要单独验收 |
| F1 | P1 | 全栈 | 插件 operation 路由缺少节点/实例定位 |
| F2 | P2 | 性能/网络 | gRPC keepalive、重连风暴、TLS 选型、端口分离 |
| F3 | P2 | 全栈/性能 | SSE、静态资源、schema 校验、幂等键细节 |
| F4 | P2 | 全栈 | 公共 API 契约来源与错误格式 |
| D1–D8 | P3 | 文档 | 链接失效、平台矛盾、状态图缺口等 |

---

## 2. 契约层（P0，冻结前必须改）

### C1. ABI 无法表达"同进程多实例"，插件放置位置未定义

**问题**

- ARCH §5.6 与 ADR A17 规定同一插件的多个实例共享进程、按 `node_id + plugin_instance_id` 隔离。但 proto 里只有 `ValidateConfigRequest`、`ApplyConfigRequest`、`InitializeRequest` 带 `instance_id`；`Start/Stop/Health/Invoke/RunJob` 和所有 Host Service 都没有。一个进程里有多个实例时，宿主无法告诉插件"这次调用的是哪个实例"，插件也无法告诉宿主"我在替哪个实例读写状态"。
- ARCH §3 规定 Controller 不执行插件代码、插件只在 Agent 下运行。但路线图里的插件商城、订阅、多用户套餐天然是全局的，需要跨节点汇总数据；`controller` 角色又没有本机 Agent。这类插件目前没有合法的运行位置。

**建议**

1. 新增 ADR，manifest 增加 `placement: node | controller`。`controller` 级插件仍不进 Controller 进程，而是由 Controller 主机上的 Agent 运行：`standalone` 的本机 Agent 同时运行两类插件；`controller` 角色也附带一个本机 Agent，但只运行 `placement=controller` 的插件，不把本机当作受管节点。
2. proto 拆成两类调用：进程级（`GetDescriptor`、进程健康）与实例级（其余全部）。实例级调用在 `RequestContext` 中带 `instance_id`，`ApplyConfigRequest` 同时补上它缺的 `node_id`。
3. 增加 `ReleaseInstance`：共享进程删除单个实例时，插件可释放该实例的内存和后台任务，而不必重启整个进程。宿主侧仍按 owner 统一清理，这个调用只是优化。
4. 订阅链接这类需要无会话公网访问的入口，单独建模为"插件注册的公开路由"：独立限流、默认关闭、需要单独能力。不要让它走 `/api/v1/plugins/...` 的会话路径。

**位置**：`platform_v1.proto:19-26, 79-85, 102-145`；ARCH §3、§5.6；ADR A17。

### C2. Host Service 的调用者身份取自插件自报字段

**问题**：插件调用 `HostState`、`HostSecrets`、`HostAudit` 时携带的 `RequestContext`（`actor_id`、`node_id`、`operation_id`）由插件自己填写。proto 只写了"State 和 Config 的 key 隐式按实例命名空间"，没有说明宿主从哪里得知是哪个实例。如果实现时信任这些字段，恶意插件可以冒充操作者写审计、读写别的实例的状态。

**建议**：在 proto 注释和 ARCH §5.4 写明身份推导规则。

- **插件身份与 generation 取自传输层**（每插件私有 UDS + `SO_PEERCRED`，见 S1），不取自消息字段。
- **实例身份使用宿主签发的不透明 `instance_handle`**：`Initialize` 时下发，插件回调宿主时携带；宿主校验它属于当前连接对应的插件与 generation。进程重启后旧 handle 全部失效，这正好实现 A13 的"新 generation 不继承旧回调"。
- 插件回传的 `actor_id`、`node_id`、`trace_id` 只用于日志关联，不参与授权。
- 插件→宿主的调用改用独立的 `HostCallContext { instance_handle, operation_id, trace_id }`，不复用宿主→插件的 `RequestContext`，从结构上避免误用。

同一插件的不同实例按 A17 本来就共享信任域，handle 防的是 SDK bug 导致的跨实例、跨 generation 串用，而不是同进程内的恶意代码。

**位置**：`platform_v1.proto:19-26, 247-266`；ARCH §5.4、§5.7。

### C3. 没有宿主中介的跨插件调用，Core Intent 无法落地

**问题**：manifest 支持 `dependencies.kind=plugin`，ARCH §9 要求上层插件通过 Core Intent 驱动 Core Driver 插件，但 ABI 里没有"插件 A 调用插件 B 的 operation"的通道。§5.6 的"经公共版本化服务/事件"只覆盖数据共享，不覆盖命令。HANDOFF §10 建议用"两个真实场景"试用 ABI，"订阅插件调用 Core Driver 的 Apply"就会在这里卡住。

**建议**：增加由宿主中介的点对点调用。

```proto
service HostInvokeService {
  rpc InvokePlugin(InvokePluginRequest) returns (InvokePluginResponse);
}
message InvokePluginRequest {
  HostCallContext context = 1;
  string target_plugin_id = 2;
  string target_instance_id = 3;
  string operation = 4;
  string api_version = 5;
  bytes payload_json = 6;
  string idempotency_key = 7;
}
```

宿主负责能力检查（如 `plugin.invoke:<plugin_id>/<operation>`、`core.intent.write:<instance>`）、schema 校验、deadline 传播、审计和路由到 ACTIVE generation。它是单次点对点调用，不是 §17 明确不采用的通用 waterfall。

**位置**：`platform_v1.proto:247-266`；ARCH §5.4、§5.6、§9。

### C4. 蓝绿期间后台任务会双跑，缺少激活阶段

**问题**：§6.3 先启动候选版、做 readiness，再切路由、旧版排空。路由切换只管请求。如果插件在 `Start` 里启动了定时器、事件订阅或周期任务，切路由之前新旧两个 generation 会同时跑后台工作，例如重复扣流量、重复发告警、重复写外部系统。

**建议**

- 生命周期增加 `Activate`：`Start` 只表示"已就绪、可接请求"，`Activate` 才表示"开始后台工作"。
- 宿主保证顺序：旧 generation 停止后台工作（`Stop(draining=true)` 的第一步）→ 新 generation `Activate`。事件订阅投递和宿主托管的定时任务只发给 ACTIVE generation。
- 不能容忍短暂双跑、也不能拆分后台工作的插件，在 manifest 里声明，强制走受控重启。

**位置**：`platform_v1.proto:102-110, 235-245`；ARCH §6.1、§6.3。

### C5. manifest 签名位置矛盾，内嵌签名有解析歧义

**问题**：schema 把 `signature` 放在 manifest.json 内部，ARCH §5.1 的包结构又有独立的 `signatures/` 目录。内嵌签名意味着验签时要"去掉 signature 字段、规范化、再比对"。只要验签时解析的 JSON 与安装时解析的 JSON 有差异（重复键、数字格式、Unicode 转义），攻击者就能构造"验签看到一份、安装执行另一份"的包。Go 的 `encoding/json` 遇到重复键时静默取最后一个值，不报错。

**建议**

- 改为分离签名：`signatures/manifest.sig` 是对 manifest.json **原始字节**的 Ed25519 签名。先验签、后解析。
- 解析时拒绝重复键和未知字段，从 schema 中删除 `signature`，保留 `publisher.key_id`。
- `files` 必须覆盖包内除 manifest 与签名外的全部文件；包内出现未列出的文件即拒绝。
- `key_id` 定义为公钥指纹（例如 `ed25519:<sha256 前缀>`），不是自由字符串。

**位置**：`manifest.schema.json:47-56`；ARCH §5.1、§10.4。

### C6. manifest 路径字段可路径穿越

**问题**：用 schema 自身的正则实测，以下值全部通过校验：

| 字段 | 通过校验的恶意值 |
|---|---|
| `entrypoint`（`^bin/[A-Za-z0-9._-]+$`） | `bin/..` |
| `operations[].request_schema`（`^schemas/`） | `schemas/../../etc/shadow` |
| `ui.entry`（`^ui/`） | `ui/../bin/plugin` |
| `files` 的键 | 无约束，可为绝对路径或含 `..` |
| `state.backup_paths[]` | 无约束 |

另外，Draft 2020-12 中 `format: "uri"` 和 `contentEncoding` 默认只是注解，不做校验，所以 `ui.connect_sources` 实际上接受任意字符串。ARCH §10.4 要求防 zip slip，schema 是第一道防线，目前没有起作用。

**建议**：在 `$defs` 定义统一的安全相对路径，所有路径字段引用它。正则不用前瞻断言，因为 Go 常用的 JSON Schema 实现使用 RE2，不支持前瞻。

```json
"$defs": {
  "relpath": {
    "type": "string", "maxLength": 255,
    "pattern": "^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$"
  },
  "https_origin": {
    "type": "string",
    "pattern": "^https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(:[0-9]{1,5})?$"
  }
}
```

每段路径不能以 `.` 开头，因此 `.`、`..` 和隐藏文件都被排除。已验证该正则拒绝 `../x`、`/etc/passwd`、`a/../b`、`a/./b`、`.hidden`、`a\b`、`a//b`、`a/` 和空串，接受 `bin/plugin`、`assets/img/logo.png`。

- `files` 增加 `"propertyNames": { "$ref": "#/$defs/relpath" }` 和 `maxProperties`。
- `entrypoint`、`request_schema`、`response_schema`、`ui.entry`、`backup_paths[]` 都引用 `relpath`，再用各自的前缀约束（如 `^schemas/`）。
- `connect_sources` 改为只接受 `https_origin`：不允许路径、通配符和 `http:`。它是插件 UI 的外发通道，安装向导要把它作为敏感权限展示。
- schema 表达不了的检查由安装器做：大小写与 Unicode 规范化后去重、`entrypoint` 与 schema 引用必须出现在 `files` 中。

**位置**：`manifest.schema.json:41-45, 69-70, 108, 137-139`。

### C7. manifest 缺少 §5.3 要求的字段，且没有演进机制

**问题**：ARCH §5.3 列出的以下内容在 schema 里没有对应字段。

| 缺失项 | 后果 |
|---|---|
| 启动策略 `eager / on_demand` | 无法在安装时校验"后台插件必须 eager"（HANDOFF §5.1） |
| SBOM / 构建来源引用 | 状态机 `VERIFIED: ... + SBOM policy` 没有输入 |
| UI 贡献点：路由、导航、所需权限 | `ui` 只有 entry、sandbox、connect_sources |
| 所需节点能力（cgroup v2、核心版本等） | 预检阶段无法拒绝不满足条件的节点 |
| 冲突 / 替代声明 | ARCH 明确要求"冲突和替代显式表达" |
| 名称、描述、图标、许可证、主页 | 安装向导和商城没有可展示的内容 |
| operation 调用方式 `invoke / job` | 宿主不知道该调 `Invoke` 还是 `RunJob`、是否返回 202 |
| `fds_max` | ARCH §10.2 要求限制文件句柄 |

此外，`update_strategy` 放在 `resources` 下语义不对；全部对象都是 `additionalProperties: false` 且 `schema_version` 是常量 `"1"`，以后增加任何可选字段都会变成破坏性变更。

**建议**

- 冻结前补齐上表字段；启动策略与 `update_strategy` 一起移入 `lifecycle`。
- `version` 加 SemVer 2.0 正则（已验证接受 `1.2.3-rc.1+build.5`，拒绝 `1.2` 和 `01.2.3`）：
  `^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`
- `schema_version` 改为 `"1.N"`：宿主接受 minor ≤ 自身支持值的 manifest，对更高 minor 明确拒绝并提示升级宿主。这与 Platform ABI 的 major/minor 规则一致，既保留"不兼容即拒绝"，又允许增加可选字段。
- `targets` 是数组，但包结构是"一个包对应一个 OS/Arch、一个 entrypoint"。改为单个 `target`，或改为 target→entrypoint 映射；`arm` 需要区分 GOARM 版本。
- 给 `operations`、`capabilities`、`files` 加 `maxItems`/`maxProperties`，manifest 整体限制大小（例如 256 KiB），避免小内存机器上解析时内存膨胀。
- manifest 的 `permission` 与 proto 的 `required_permission` 统一命名。

**位置**：`manifest.schema.json:13-15, 35-40, 57-73, 120-141`；ARCH §5.3。

### C8. 配置校验没有字段级错误结构

**问题**：ARCH §5.5 要求设置页显示"字段级错误"，HANDOFF §6.2 写明"后端预留预检和字段级错误"。但 `ValidateConfigResponse` 只有 `repeated string warnings` 和一个 `ErrorDetail`，无法指出是哪个字段出错。

**建议**

```proto
message FieldViolation {
  string pointer = 1;   // RFC 6901 JSON Pointer，如 /inbounds/0/port
  string code = 2;      // 机器可读，如 PORT_IN_USE
  string message = 3;   // 面向用户
}
message ValidateConfigResponse {
  repeated FieldViolation violations = 1;
  repeated FieldViolation warnings = 2;
  ErrorDetail error = 3;
}
```

这是架构正文已经确认的需求，不属于"预留猜测性字段"。

**位置**：`platform_v1.proto:74-77`。

### C9. 事件发布可伪造宿主字段，可靠订阅没有 ack

**问题**

- `PublishEventRequest` 让插件提交完整 `Event`，其中 `event_id`、`sequence`、`occurred_at`、`delivery_class` 都应由宿主分配。注释只在 `delivery_class` 上写了"不信任插件"，实现时很容易漏掉其余字段。
- `SubscribeRequest` 有 `last_acked_sequence`，但没有 ack 调用。server stream 只能知道"已发送"，不知道"已处理"，可靠事件的语义不完整。
- ARCH §4.2 列出的事件字段（`global_seq`、`node_id`、`actor`、`trace_id`、`classification`）与 proto `Event` 对不上。
- §10.3 的能力示例只有 `events.publish:<topic>`，没有订阅能力。

**建议**：发布改用只含插件可控字段的 `EventDraft { type, schema_version, subject, payload_json }`，其余字段全部由宿主填写，从结构上杜绝伪造。可靠事件明确为 at-least-once：插件重连时用 `last_acked_sequence` 续传，或增加 `AckEvents` 调用，插件侧按 `event_id` 去重。统一 §4.2 与 proto 的字段名，增加 `events.subscribe:<topic>` 能力。

**位置**：`platform_v1.proto:179-203`；ARCH §4.2、§10.3。

### C10. proto 过不了 Buf 默认 lint，命名会固化进 wire

**问题**：Buf 在 `buf.yaml` 没有 lint 配置时默认使用 STANDARD 规则集，HANDOFF §11.3 把 `buf lint` 设为 CI 门禁。当前 proto 至少违反三条规则：

- `SERVICE_SUFFIX`：6 个 service 都没有 `Service` 后缀。
- `RPC_REQUEST_STANDARD_NAME` / `RPC_RESPONSE_STANDARD_NAME`：请求和响应必须命名为 `MethodNameRequest/Response` 或 `ServiceNameMethodNameRequest/Response`。`HostState.Get` 用的是 `StateGetRequest`；`RunJob` 流式返回 `JobProgress`，而 `RunJobResponse` 定义了却没用；`Subscribe` 直接返回 `Event`。
- `PACKAGE_DIRECTORY_MATCH`：package `panel.platform.v1` 要求文件位于模块根下的 `panel/platform/v1/`。ARCH §14 规划的 `api/platform/v1/` 不匹配。

service 名和方法名会出现在 gRPC 的 wire path（`/panel.platform.v1.Plugin/Invoke`）里，冻结后再改就是破坏性变更，只能现在改。

**建议**：`Plugin` 改为 `PluginService`，`HostState` 改为 `HostStateService`，其余同理；方法改为 `GetState/PutState/DeleteState`、`PublishEvent/SubscribeEvents`、`GetConfig`、`RevealSecret`、`WriteAudit`，请求/响应随之改名；`RunJob` 流式返回 `RunJobResponse { JobProgress progress = 1; }`。目录改为 `api/panel/platform/v1/platform.proto`（Buf 模块根为 `api/`），或者把 package 改成 `platform.v1`。`go_package` 用 Buf managed mode 生成，不在 proto 里写死占位路径。

**位置**：`platform_v1.proto:3-5, 138-145, 156-231, 235-266`；ARCH §14。

### C11. Secret 明文返回，缺少绑定与审计约束

**问题**：`HostSecrets.Use` 直接以 `string value` 返回明文。ARCH §5.6 要求"插件只能在已授权操作中短暂取值"，但契约没有表达"已授权操作"和"短暂"。`purpose` 是插件自报的字符串，不能作为授权依据。另外，配置快照不可变且至少保留 20 份或 30 天，还会进入备份；如果插件的 config schema 里有密码字段，明文会长期留在配置历史里。

**建议**

- 改名为 `RevealSecret`，对应能力 `secret.reveal:<reference>`，名字本身说明会暴露明文。
- 请求必须带 `operation_id`，宿主校验该 operation 正在派发给本插件实例；每次取值写审计并限频。
- 值改为 `bytes`，支持二进制密钥，SDK 用完后可以清零（尽力而为，不能作为保证）。
- 能由宿主代做的敏感动作（签名、带凭据建立连接）优先由宿主代做，不返回明文。
- config.schema 中用 `writeOnly: true` 或自定义关键字 `x-secret` 标记敏感字段。宿主保存配置时把它替换为 secret 引用，配置历史、事件、导出和备份中都不出现明文。

**位置**：`platform_v1.proto:214-219, 261-263`；ARCH §5.6、§6.5。

### 其他契约细节（P2，冻结前顺手改）

- `RequestContext.deadline_unix_ms` 与 gRPC 自带的 deadline 重复，时钟跳变时两者还会冲突。以 gRPC deadline 为准，删除该字段或注明只用于展示。
- `StatePutRequest.expected_revision` 为空时，是"无条件写"还是"必须不存在"？改为 `oneof precondition { bool must_not_exist = 4; string expected_revision = 5; }`，不设置即无条件写。
- KV 没有单值大小、单实例总量和键长度的上限，应在 manifest `resources` 或宿主策略中给出默认值。
- `HostConfig.Get` 与 `Initialize`/`ApplyConfig` 下发的配置职责重叠，需要写明它读的是插件自身的生效配置还是宿主公开设置。
- `HealthResponse` 没有说明是进程级还是实例级，按 C1 的拆分写明。

---

## 3. 安全与运行时（P1）

### S1. 插件拉起路径与 Agent 权限矛盾；go-plugin 的限制未纳入设计

**问题**

- ARCH §3 规定 `panel-agent` 以"普通系统用户"运行，§10.2 又要求每插件独立用户、systemd sandbox 和 cgroup v2。普通用户进程既不能把子进程切换到别的 UID，也不能给子进程套 systemd sandbox。go-plugin 默认由父进程直接 exec 子进程，与这两条同时冲突。缺的是"谁来拉起插件"这一环。
- go-plugin 的 `ClientConfig` 文档写明：`AutoMTLS` 不能与 `Reattach` 同时使用，`SecureConfig`（可执行文件校验和）不能与 `Reattach` 同时使用，`GRPCBrokerMultiplex` 不支持 Reattach。§6.4 要求宿主重启后通过 Reattach 恢复插件，所以这三项都不能作为安全基础。

**建议**（写入新 ADR）

- **拉起**：插件由 systemd 通过模板单元 `panel-plugin@<id>.service` 拉起。单元内容归 root，由安装包提供；资源限制等 drop-in 由 privileged helper 根据已校验的 manifest 渲染。Agent 只被授权启停 `panel-plugin@*`（polkit 规则按单元名和动作限定，或经 privileged helper），不能定义单元内容，否则等于给 Agent 任意 root 执行权。
- **UID**：二选一并写入 ADR。`DynamicUser=yes` + `StateDirectory=`，卸载不留系统用户；或者安装时创建固定的 `panel-p-<id>` 用户。
- **连接**：用 go-plugin 的 `PLUGIN_UNIX_SOCKET_DIR` 把插件 socket 放进每插件私有目录，Agent 用 `ReattachConfig` 连接。首次启动和宿主重启恢复走同一条路径，§6.4 的"PID 复用校验"由 systemd 的 MainPID 与 cgroup 归属代替。停止和强杀用 `systemctl stop/kill`，按 cgroup 杀干净所有子进程。
- **完整性**：用 SecureConfig 之外的方式保证。安装时校验摘要，包目录归 root 且只读（`ProtectSystem=strict`），启动前再做一次摘要校验。
- **传输认证**：每个插件的 socket 目录只有该插件和 Agent 可访问。插件与 Agent 是不同 UID，`UMask=0077` 下 socket 默认对 Agent 不可连，需要 privileged helper 设置 ACL，或使用每插件独立的组（go-plugin 支持 `PLUGIN_UNIX_SOCKET_GROUP`）。**不能让所有插件共用一个 socket 组**，否则插件 A 可以直接连插件 B 的 gRPC 服务、绕过宿主 RBAC。双向用 `SO_PEERCRED` 校验对端：Agent 由对端 PID 查 `/proc/<pid>/cgroup` 得到单元名，确认是预期插件；插件 SDK 只接受 Agent 的 UID。内核 ≥ 6.5 可用 `SO_PEERPIDFD` 消除 PID 复用窗口。
- **Host Service**：不走 go-plugin broker，由 Agent 为每个插件单独监听一个 UDS，身份按上一条识别。这样 Agent 重启不受 broker 与 Reattach 互斥的影响。
- **凭据传递**：systemd 的 `Environment=` 会经 D-Bus 暴露给非特权客户端，systemd.exec 文档明确不建议用它传 secret。所以 §10.2 中"环境变量只传……短期凭证"要改：环境变量只传实例 ID 和 socket 路径，短期凭证在连接建立后经已认证的 socket 下发，或用 `LoadCredential=`（systemd ≥ 247）。

**位置**：ARCH §3、§6.4、§10.1–10.2；ADR A03、A08。

### S2. 缺少可执行的默认沙箱模板与验收门槛

**问题**：§10.2 只给了方向（NoNewPrivileges、只读根、私有 tmp、系统调用策略），没有可落地的模板，也没有验收手段。没有基线，后续每个插件都会"按需放宽"。

**建议**：第三方插件默认模板如下，由宿主维护，插件不能直接声明 systemd 指令。

```ini
# 注意：systemd 单元文件不支持行尾注释，注释必须单独成行。
[Service]
RuntimeDirectory=panel/plugins/%i
StateDirectory=panel/plugins/%i
Environment=PLUGIN_UNIX_SOCKET_DIR=%t/panel/plugins/%i
# 默认无网络：比 IPAddressDeny 更彻底，也隔离抽象命名空间 UDS
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
# ProtectProc 需要 systemd >= 247
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
# Go 没有 JIT，可以开启
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
# 被拒的系统调用返回 EPERM，而不是用 SIGSYS 杀进程
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077
KeyringMode=private
# MemoryHigh= MemoryMax= CPUQuota= TasksMax= LimitNOFILE= 由 manifest 渲染到 drop-in
```

- 能力到放宽项的映射由宿主统一定义，例如 `network.egress:<policy>` 对应取消 `PrivateNetwork`、经 UDS 接入宿主出站代理；`metrics.read:host` 对应放宽 `ProtectProc/ProcSubset`。插件只申请能力，不能申请"关掉某条指令"。
- 出站代理默认拒绝 loopback、链路本地（含云厂商元数据地址 `169.254.169.254`）、RFC 1918/ULA 私网和本机地址，需要时逐项放开。
- CI 和 `panel doctor` 用 `systemd-analyze security panel-plugin@<id>.service` 打分，设阈值，超过阈值即失败。
- 模板必须在目标发行版上用真实插件跑过一遍。`SystemCallFilter` 的分组随 systemd 版本变化，设置 `EPERM` 后出问题更容易定位。

**位置**：ARCH §10.2；HANDOFF §10"go-plugin 不是安全沙箱"一行。

### S3. 把 loopback 当信任边界

**问题**：§13 的 pprof"仅本机"、§9 的 Xray API"仅监听本机"都假设 127.0.0.1 是安全边界。同一台机器上任何进程都能连 127.0.0.1，包括拿到网络能力的插件、降级沙箱下的插件和被攻破的代理核心。Xray API 能增删入站和用户，连上它就等于接管代理核心；pprof 的 heap profile 可能包含会话 token 和密钥。

**建议**

- 宿主自身的调试和管理端点只走 UDS + 文件权限 + `SO_PEERCRED`。pprof 需要显式开启，超时自动关闭。
- 必须使用 TCP loopback 的上游接口（如 Xray API）只允许对应的 Core Driver 访问；其他插件依靠 `PrivateNetwork=yes` 和出站代理的 loopback 拒绝规则挡住。
- 不使用抽象命名空间 UDS（`@name`）。它没有文件权限，同一网络命名空间内的任何进程都能连。

**位置**：ARCH §9、§13。

### S4. 首次 enroll 没有固定 Controller 身份

**问题**：§3.2 中 Agent 在第 2 步发起 enroll，第 3 步才拿到 Controller CA。Controller 使用自签名证书或只有 IP 时，Agent 首次连接没有信任锚。持有 token 的中间人可以冒充 Controller、下发自己的 CA，之后经 privileged helper 获得节点上的 root 级操作。

**建议**

- 安装命令携带 Controller CA 的公钥指纹，Agent 首次连接时校验，做法同 kubeadm 的 `--discovery-token-ca-cert-hash sha256:…`。Controller 使用公开 CA 签发的证书时，可以改用常规证书校验。
- Controller 签发证书时忽略 CSR 中的 Subject 和 SAN，只写入自己分配的 `node_id`（例如 URI SAN `panel://node/<id>`）。此后所有消息的 `node_id` 都从证书取，不信任消息体中的值。
- 节点证书短有效期（如 30 天），在会话内自动轮换。Controller 是唯一校验方，吊销在握手时查本地 deny-list 即可，不需要 CRL/OCSP。
- 签发时 `NotBefore` 回拨几分钟以容忍时钟偏差；`panel doctor` 检查时间同步。
- CA 私钥与 Controller 对外 HTTPS 证书的私钥分开存放。

**位置**：ARCH §3.2。

### S5. Controller 失陷即全部节点 root 失陷

**问题**：Controller 能向任意节点下发插件和 `system.service.manage` 这类高敏能力。Controller 一旦失陷，所有节点随之失陷。这是多节点面板的通病，ARCH 没有讨论。

**建议**：不改变 Controller 作为控制面的角色，在节点侧加两道兜底。

- Agent 用**自己的信任根**校验插件包签名，不只信任"Controller 已校验过"。Controller 失陷后也无法推送未签名或非受信发布者的包。
- 节点本地策略文件（归 root，Controller 不可写）可以禁止远程安装第三方插件、禁止某些高敏能力，或者对"只做探针"的节点完全关闭远程命令。
- 高敏能力首次授予时，在节点本地留一条 Controller 无法删除的审计记录。

**位置**：ARCH §3.2、§10.3。

### S6. 节点/插件上报内容未按不可信处理

**问题**：Agent 证书有效只能证明"这是那个节点"，不能证明内容可信，因为节点本身也可能被攻破。主机名、进程名、错误信息、`details_json`、Job 进度消息、插件名称和能力说明都会显示在持有管理员会话的 Shell 里，这是存储型 XSS 的主要入口。

**建议**

- Controller 对节点消息限制大小、频率和 schema；`node_id` 只从证书取。
- Shell 对所有来自节点和插件的字符串只做文本渲染：禁止 `innerHTML`，Markdown 渲染禁用 HTML。
- 插件图标只用 `<img>` 显示，不把 SVG 内联进 DOM。内联 SVG 可以执行脚本，`<img>` 中的 SVG 不能。

**位置**：ARCH §4.1、§5.5。

### S7. sandbox iframe 缺少几条关键细则

**问题与建议**

- `sandbox` 只给 `allow-scripts`，按需加 `allow-forms`、`allow-downloads`。**`allow-scripts` 与 `allow-same-origin` 不能同时出现**：MDN 明确警告，两者同时出现时，同源的嵌入文档可以移除自己的 sandbox 属性。同样禁止 `allow-top-navigation*` 和 `allow-popups-to-escape-sandbox`。
- 插件静态资源的响应头带 `Content-Security-Policy: sandbox allow-scripts; …` 和 `X-Content-Type-Options: nosniff`。这样即使有人直接打开 URL，页面仍在沙箱里；伪装成图片的 HTML 也不会被执行。
- 不带 `allow-same-origin` 时 iframe 的 origin 是 `"null"`，`event.origin` 无法区分插件。Shell 应校验 `event.source === iframe.contentWindow`，并为每个 iframe 建立专用 `MessageChannel`，之后只经转交的 port 通信。port 不可伪造，可以替代"一次性 channel token"。
- 宿主 API 的 CORS 永远不允许 `Origin: null`。
- 桥接层只代理该插件自己的 operation 命名空间，不代理宿主级 API（用户、节点、插件管理）和其他插件的 API，避免插件 UI 借管理员会话做越权操作（confused deputy）。
- 不要把"不同端口"当作 Cookie 隔离：按 RFC 6265，Cookie 不按端口隔离。

**位置**：ARCH §5.5。

### S8. 管理入口缺少首次初始化、TLS、MFA、防锁死的设计

**问题**：HANDOFF §9.1 把 TLS 方案和身份体系列为未决。面板持有 root 级操作，以下几项会影响 P1 的数据模型，需要现在定。

**建议**

- **首次初始化**：不设默认密码。安装时打印一次性初始化链接（含 token），用完即失效；或者默认只监听 `127.0.0.1`，经 SSH 隧道完成初始化。
- **TLS**：任何情况下都不在公网明文提供登录页。有域名时用 ACME；没有域名时生成自签名证书，并在安装输出中打印指纹供用户核对。
- **MFA**：身份模型现在就预留 TOTP/WebAuthn，以及敏感操作（安装插件、授予高敏能力、删除数据）的二次验证。
- **登录限速**：按账号 + IP 做渐进退避，不做硬锁定，否则攻击者可以故意锁死管理员。口令哈希（argon2id）用信号量限制并发，内存参数按机器档位设置，避免并发登录耗尽 1G 内存。
- **代理头**：只信任来自已配置反代地址的 `X-Forwarded-For`，否则伪造该头即可绕过按 IP 限速。
- **WebSocket/SSE**：握手校验 `Origin`（防 CSWSH）和 `Host` 白名单（防 DNS rebinding，桌面端监听 localhost 时尤其需要）。
- **会话**：Cookie 设 `HttpOnly; Secure; SameSite=Lax`；登录和提权时轮换会话 ID；设空闲超时和绝对超时。所有变更请求必须带 `Idempotency-Key`，这也让跨站表单无法直接提交（自定义头会触发 CORS 预检），可作为 CSRF token 之外的第二道防线。
- **本地恢复**：提供仅 root 可用的 `panel recover`，用于重置管理员、关闭 MFA、恢复监听配置，全部写审计。
- **防锁死**：凡是会改变可达性的系统能力（防火墙、SSH、面板端口/TLS），统一采用"应用 → 倒计时确认 → 超时自动回滚"。这与本项目的事务式更新思路一致，应作为 Host Capability 的通用规则，不留给各插件自行实现。

**位置**：HANDOFF §9.1；ARCH §4、§10。

### S9. 供应链：索引防回滚、解包实现、远程 `$ref`

**建议**

- §10.4 要求的"索引签名、过期、密钥轮换、撤销"正是 TUF（The Update Framework）解决的问题，Go 有 `go-tuf`。直接采用 TUF 模型，不自造。本地记录见过的最高版本，拒绝索引回滚和冻结攻击；降级插件必须由用户显式操作。
- SBOM 与构建来源使用 in-toto/SLSA 证明格式，供 C7 的 manifest 字段引用。
- 解包使用 Go 1.24 的 `os.Root`，把所有文件操作限制在目标目录内，防符号链接逃逸；拒绝符号链接、硬链接、设备文件和 setuid 位。
- 包文件归 root 且只读，插件被攻破后无法改写自己的二进制来持久化。
- 插件的 JSON Schema 禁止远程 `$ref`，只允许包内引用，否则 schema 加载器会成为 SSRF 入口。
- 给 manifest 解析、解包、schema 加载、节点协议和 postMessage 处理加 Go 原生 fuzz 测试。

**位置**：ARCH §10.4、§16。

### S10. 插件可借审计/日志洪泛对宿主施压

**问题**：§4.2 规定审计"超限触发背压"。如果插件写的审计与宿主自身审计共用队列和配额，恶意插件刷审计就能通过背压拖慢宿主的关键写入。插件的 stderr 经 go-plugin 转给 Agent 解析，刷日志也会消耗 Agent 的 CPU。

**建议**：插件审计与宿主审计分开配额并标注来源，超限只限流该插件；`actor`、时间和插件身份由宿主填写，不采信插件提交的值。Agent 按插件限制日志读取速率和单行长度，超出部分丢弃并计数。

**位置**：ARCH §4.2、§13。

---

## 4. 运维与资源（P1–P2）

### O1. 支持矩阵缺少虚拟化类型和 cgroup 版本（P1）

**问题**：HANDOFF §9.1 只列了"发行版和 systemd 最低版本"。低价 VPS 常见 OpenVZ/LXC 容器，往往没有完整的 cgroup v2 委派，也缺少 systemd sandbox 需要的命名空间；老发行版可能仍是 cgroup v1。S2 的模板在这些环境里会部分失效。

**建议**

- 安装器和 `panel doctor` 探测 `systemd-detect-virt`、cgroup 版本与可用控制器、systemd 版本、命名空间和 seccomp 是否可用。
- 隔离前提不满足时，第三方插件默认拒绝安装；用户显式接受风险后可以安装，该决定写入审计，并在 UI 中持续提示。内置插件允许降级运行。
- 沙箱模板按 systemd 版本选择指令，不假设所有指令都可用。

**位置**：HANDOFF §9.1 第 3 项；ARCH §10.2。

### O2. 1G 内存保护缺少 GOMEMLIMIT、MemoryHigh、OOM 优先级（P1）

**问题**：设计里有更新前的内存 preflight，但没有运行时的防线。Go 1.25 起运行时会按 cgroup 的 CPU 限额设置 GOMAXPROCS，但**不读取 cgroup 内存上限**。插件的堆会一直增长，直到被 OOM killer 杀掉，而 GC 并不知道上限在哪里。

**建议**

- Supervisor 给每个插件设置 `GOMEMLIMIT ≈ 0.85 × memory_max_mb`，让 GC 在触顶前加速回收；宿主进程同样处理。
- systemd 同时设置 `MemoryHigh`（约 0.9 × MemoryMax）和 `MemoryMax`：先限速回收，再 OOM。
- `OOMScoreAdjust`：Controller/Agent 设负值，插件设正值。内存不足时内核先杀插件，保住控制面。
- preflight 读 `/proc/meminfo` 的 `MemAvailable`（不是 `MemFree`），结合 cgroup 的 `memory.current`。
- 1G 且无 swap 的机器，`panel doctor` 提示可选启用 zram，但不自动修改系统。
- 不对 Go 二进制使用 UPX。解压后的代码段变成匿名页，内存紧张时无法像文件页那样丢弃后重读，在无 swap 机器上更容易 OOM。`-trimpath -ldflags="-s -w"` 已足够。

**位置**：ARCH §6.3、§13.1。

### O3. SQLite 写入纪律与插件 KV 存放位置（P2）

**建议**

- 一个写连接加一个小的只读连接池。所有写事务以 `BEGIN IMMEDIATE` 开始（经驱动的 DSN 参数或显式语句）。WAL 模式下，延迟事务从读升级为写时，如果期间已有其他写入提交，会直接返回 `SQLITE_BUSY`，`busy_timeout` 救不了。
- 组提交：节点事件、指标批次和 outbox 记录按时间窗或条数合并为一个事务。SQLite 的吞吐瓶颈主要是每个事务一次 fsync，而不是语句数量。
- `synchronous`：WAL 下 `NORMAL` 在断电时可能丢最近的事务，但不会损坏数据库。审计要求"不静默丢弃"，建议保持 `FULL`，用组提交摊薄成本；压测确有瓶颈时再评估。
- 长时间的读事务（例如在 SSE 处理过程中持有读事务）会阻止 WAL 检查点，WAL 文件持续增长。读事务要短，设置 `journal_size_limit`，空闲时执行 `wal_checkpoint(TRUNCATE)`，并监控 WAL 大小。
- 备份用 `VACUUM INTO` 或在线备份 API，与 §8.3"文件拷贝不等于一致性备份"一致。
- 每个连接有独立的页缓存，1G 机器要限制 `cache_size` 和连接数。
- **插件 KV 不放 Controller DB**，放在 Agent 本地、每插件一个文件。否则插件写入与控制面写入争抢同一把写锁，插件可以间接拖慢登录和 operation；单独的文件也便于配额、备份和卸载清理。
- outbox 投递在提交后由进程内信号唤醒投递器，低频轮询只作兜底，不做高频轮询。

**位置**：ARCH §5.6、§7、§8。

### O4. 目录布局、宿主发布/回滚与安装器（P2）

**建议**：使用 FHS 布局，宿主版本目录不可变，回滚只切换链接。

```text
/opt/panel/releases/<version>/      宿主二进制（不可变）
/opt/panel/current -> releases/<v>  回滚 = 切换链接 + 重启 + 兼容快照
/var/lib/panel/                     数据（DB、插件包、插件状态）
/etc/panel/                         配置与节点本地策略（S5）
/var/log/panel/                     有界日志
/run/panel/                         socket（RuntimeDirectory 管理）
```

安装脚本本身签名，用固定公钥校验；提供离线安装包；可重复执行（幂等）；卸载默认保留数据。宿主自更新与插件一样，经离线根密钥签发的发布密钥验证，与 HANDOFF §10"签名密钥运营"合并设计。

**位置**：ARCH §12；HANDOFF §2"部署"一行。

### O5. 日志洪泛、健康端点、诊断包、磁盘配额实现（P2）

- journald 的配额由全系统共享，啰嗦的插件会把系统日志挤掉。插件单元设置 `LogRateLimitIntervalSec`/`LogRateLimitBurst`，或用 `LogNamespace=` 隔离。
- 提供 `/healthz`（存活）和 `/readyz`（就绪）。§12 宿主升级的"readiness 通过后接受新请求"以 `/readyz` 为准。
- `panel support-bundle` 导出脱敏诊断包，便于用户报障。
- 证书到期、磁盘空间、备份失败的告警属于宿主健康，不依赖插件。
- **`disk_max_mb` 的实现要写清**：cgroup v2 不限制磁盘空间，多数 VPS 的 ext4 也没有开启 prjquota。首版建议"定期统计 + 软限制 + 告警"，并在文档中说明它不是硬限制。

**位置**：ARCH §13；`manifest.schema.json:128`。

### O6. 探针形态的真实内存成本需要单独验收（P2）

**问题**：内置模块也走插件进程，所以"只做探针"的节点实际运行 Agent 和基础监控插件两个进程，按 §13.1 的预算合计约 30–55 MiB。探针用户常把节点装在 256–512 MiB 的小机器上，单看"Agent 15–25 MiB"会低估成本。

**建议**：把"Agent + 基础监控插件"列为单独的验收档位，在 512 MiB 容器中实测。基础监控插件是第一个插件，同时把它作为插件 RSS 的基准。

**位置**：HANDOFF §8.2；ARCH §13.1。

---

## 5. 全栈与性能（P1–P2）

### F1. 插件 operation 路由缺少节点/实例定位（P1）

**问题**：`POST /api/v1/plugins/{plugin_id}/operations/{operation}` 在多节点下无法指定目标节点和实例，RBAC 也无法按节点授权。它属于对外稳定契约，越晚改代价越大。

**建议**：改为 `/api/v1/nodes/{node_id}/plugins/{plugin_id}/instances/{instance_id}/operations/{operation}`；`placement=controller` 的插件用 `/api/v1/plugins/{plugin_id}/operations/{operation}`。RBAC 的 resource 包含 `node_id`。

**位置**：ARCH §4.1。

### F2. 节点连接：keepalive、重连风暴、TLS、端口（P2）

- gRPC keepalive：Agent 的 ping 间隔必须大于 Controller 的 `EnforcementPolicy.MinTime`，否则 Controller 会以 `too_many_pings` 发送 GOAWAY，形成断线循环。NAT 环境建议 30–60 秒。
- Controller 重启后，所有 Agent 同时重连会让单核机器的 TLS 握手排队。重连使用带抖动的指数退避，并启用 TLS 1.3 会话恢复。
- 节点证书使用 ECDSA P-256 或 Ed25519，握手 CPU 成本低于 RSA。
- 节点通道与浏览器 HTTPS 分开端口。节点端口强制客户端证书、只允许 TLS 1.3，可以单独对节点 IP 开放防火墙。共用一个端口时，容易出现某条路径漏验客户端证书。

**位置**：ARCH §2.1、§3.2、§12。

### F3. SSE、静态资源、schema 校验、幂等键（P2）

- **SSE**：每个标签页一条连接，按 topic 订阅复用，不为每个组件各开一条（HTTP/1.1 下浏览器对同一主机最多约 6 条连接）。心跳小于 30 秒，避免反代超时断开；文档给出 Nginx 的 `proxy_buffering off` 与超时配置。每条连接的缓冲有界，慢客户端断开后用快照重同步。
- **静态资源**：Shell 资源文件名带内容哈希、设置长缓存，构建时预压缩（gzip/brotli）。只用系统字体，不加载 Web 字体。
- **schema 校验**：安装时编译并缓存 schema；校验前先限制请求体大小和 JSON 嵌套深度，单核机器上大请求的校验很耗 CPU。Go 的 `regexp` 是线性时间，后端没有 ReDoS 风险；但如果 Shell 在前端用插件提供的 `pattern` 做即时校验，JS 正则会回溯，恶意 schema 可以卡死管理员浏览器。前端只做类型和必填检查，`pattern` 交给后端。
- **幂等键**：作用域为"用户 + 路由"，设置 TTL（如 24 小时）和容量上限；同一个键的并发请求，第二个返回 409 或等待第一个完成；body 比较用规范化后的哈希。

**位置**：ARCH §4.1、§13.1。

### F4. 公共 API 契约来源与错误格式（P2）

- 公共 DTO 以 OpenAPI 3.1 为唯一来源，生成 Shell 的 TypeScript 客户端和 `clientcore` 的 Go 客户端，避免三端手写 DTO 后逐渐不一致。
- 错误格式可以对齐 RFC 9457 Problem Details（`application/problem+json`），把现有的 `code`、`retryable`、`request_id` 作为扩展字段。
- 插件 UI 在 sandbox iframe 里读不到宿主的 CSS 变量，需要"版本化 UI Kit + 桥接消息下发主题"。详见仓库根目录 `ui-design/DESIGN.md` §7。

**位置**：ARCH §4.1、§5.5、§11。

---

## 6. 文档一致性（P3）

| 编号 | 问题 | 建议 |
|---|---|---|
| D1 | 链接指向 `contracts/`、`adr/`，HANDOFF 还写了资料位于 `/workspace/architecture/`；实际五个文件都在根目录。HANDOFF §2.1 却写"文档内部链接和引用完整" | 按 HANDOFF §13 建议的结构移动文件，或修正链接（ARCH:222, 235；HANDOFF:14, 25-27, 432-434） |
| D2 | §11 写 Desktop"可嵌入完整 standalone 核心"，同节又标注 controller/agent/pluginruntime 为 Linux only（依赖 systemd/cgroup） | 写明只有 Linux 桌面能嵌入完整核心；Windows/macOS 只做远程客户端，或另定义"无插件沙箱的本地受限模式" |
| D3 | §6.1 状态图中 DOWNLOADING/VERIFIED/STAGED 没有失败出口；ROLLED_BACK、QUARANTINED 之后去向未定义；§6.6 的 CLEANUP_FAILED 不在图中；版本状态与安装状态混在一张图里 | 拆成"版本生命周期"和"安装/卸载生命周期"两张图，补齐失败与人工解除路径 |
| D4 | §1.3"任意时刻一个插件最多一个 ACTIVE 版本"与 §12 的 Agent 独立灰度矛盾：灰度期间不同节点的版本可以不同 | 改为"每个节点上每个插件实例" |
| D5 | §6.5"至少保留最近 20 个或 30 天，以先到者为准"有歧义 | 写成"保留最近 20 个，且保留 30 天内的全部"（取并集），或者按实际意图改写 |
| D6 | §4.2 事件字段与 proto `Event` 不一致；manifest 用 `permission`，proto 用 `required_permission` | 随 C9、C7 统一 |
| D7 | HANDOFF §11.3 的 `go test -race` 需要 `CGO_ENABLED=1` 和 C 编译器（Go 官方文档），与默认 `CGO_ENABLED=0` 不冲突，但必须分成两个 CI job | race 测试 job 开 CGO；发布构建 job 关 CGO |
| D8 | 插件放置（C1）和插件拉起路径（S1）是新的架构决策 | 新增 ADR-0002、ADR-0003，不直接改 ADR-0001 |

---

## 7. 建议的落地顺序

| 阶段 | 先完成 |
|---|---|
| P0 契约冻结前 | C1–C11、F1、D1、D8（两份新 ADR） |
| P1 最小宿主 | S8、O3、O4、F3、F4 |
| P2 插件运行时 | S1、S2、S3、S10、O1、O2、O5 |
| P3 热更新 | C4 的激活顺序与故障注入测试 |
| P4 节点化 | S4、S5、S6、F2 |
| P5 UI 扩展点 | S7，以及 `ui-design/` 中的主题桥 |
| P6 基础插件 | O6 |

建议在 ARCH §16 的测试清单中增加：

- 插件 A 尝试连接插件 B 的 socket、伪造 `instance_handle`、伪造事件的 `sequence`。
- 在没有固定 CA 指纹的情况下，中间人冒充 Controller 进行 enroll。
- 蓝绿窗口内统计后台任务的执行次数，必须为 1。
- manifest 中出现路径穿越、重复键、超大 `files`。
- `systemd-analyze security` 分数门禁。
- 1G 无 swap 机器上并发登录 + 插件更新时的内存峰值；SQLite 在组提交下没有因 `SQLITE_BUSY` 失败的写入。

## 8. 与现有理念的一致性核对

- 没有引入消息队列、新数据库或 Kubernetes；SQLite 单写不变。
- 没有把任何插件放进宿主进程；`placement=controller` 的插件仍运行在独立的 Agent 之下。
- 跨插件调用是带能力检查的点对点宿主中介调用，不是通用 waterfall。
- 没有新增通用 shell、文件或网络能力；出站代理默认拒绝。
- systemd 拉起、UDS 认证、`GOMEMLIMIT` 都不增加空闲内存；没有新增常驻组件。
- proto 和 manifest 的新增字段都对应架构正文已经写明的需求，不是为未知需求预留。

## 9. 落实情况（v1.1）

| 编号 | 落点 | 施工任务 |
|---|---|---|
| C1 | ADR-0002；proto `RequestContext.instance_id`、`ReleaseInstance`；manifest `placement` | P0-T3、P2-T4 |
| C2 | proto 文件头身份规则、`HostCallContext`；ARCH §5.4；ADR-0003 第 4 条 | P2-T2、P2-T6 |
| C3 | proto `HostInvokeService.InvokePlugin`；ARCH §5.4 | P2-T6 |
| C4 | proto `Activate/Deactivate`；manifest `lifecycle.background/overlap_safe`；ARCH §6.3 | P3 |
| C5 | 分离签名 `signatures/manifest.sig`；schema 删除 `signature`；ARCH §5.1、§10.4 | P0-T4、P2-T3 |
| C6 | schema `$defs.relpath/https_origin`；`tools/manifest_check.py` 负例 | P0-T4 |
| C7 | schema 新增 lifecycle、provenance、ui.routes、node_requirements、conflicts、display 字段、operation 元数据、`fds_max`、SemVer、`schema_version=1.N`、单个 `target` | P0-T4 |
| C8 | proto `FieldViolation`、`ValidateConfigResponse.violations` | P0-T3 |
| C9 | proto `EventDraft`、`AckEvents`、`Event` 字段对齐；能力 `events.subscribe` | P0-T3、P2-T6 |
| C10 | 全部 service/RPC 按 Buf STANDARD 重命名；目录 `api/qwq/platform/v1/`；去掉 `go_package` | P0-T3 |
| C11 | proto `RevealSecret`（bytes、operation_id）；能力 `secret.reveal`；config `writeOnly/x-secret` | P1-T6、P2-T6 |
| S1 | ADR-0003 | P2-T1、P2-T5 |
| S2 | ARCH §10.2；本文 S2 模板 | P2-T5、P2-T8 |
| S3 | ARCH §9、§10.2、§13 | P2-T5 |
| S4 | ARCH §3.2 | P4 |
| S5 | ARCH §10.2 节点侧兜底 | P4 |
| S6 | ARCH §3.2、§5.5 | P1-T7、P5 |
| S7 | ARCH §5.5；`ui-design/DESIGN.md` §7 | P5 |
| S8 | ARCH §4.1.1 | P1-T3、P1-T7、P1-T9 |
| S9 | ARCH §6.2、§10.4 | P2-T3、P6 之前的商城 |
| S10 | ARCH §4.2 | P2-T6、P2-T7 |
| O1 | ARCH §10.2、§13 `qwq doctor` | P2-T8 |
| O2 | ARCH §6.3 运行时内存防线；ADR-0003 第 7 条 | P2-T5、P2-T7 |
| O3 | ARCH §5.6、§8.1 写入纪律 | P1-T2 |
| O4 | ARCH §12 目录与发布 | P1-T10 |
| O5 | ARCH §13 | P1-T10、P2-T7 |
| O6 | ARCH §13.1 探针档位 | P6 |
| F1 | ADR-0002；ARCH §4.1 | P1-T7 |
| F2 | ARCH §3.2 第 6 条；本文 F2 | P4 |
| F3 | ARCH §4.1 | P1-T7 |
| F4 | ARCH §4.1（OpenAPI 3.1、RFC 9457） | P0-T5 |
| D1–D8 | 目录重组与链接修正；ARCH §1.3、§6.1、§6.5、§11；HANDOFF §11.3；ADR-0002/0003 | 已完成 |

审查之后新增的 ADR-0004（AI 原生操作面）同样已合入 proto、manifest 与 ARCH，施工任务见 `IMPLEMENTATION-PLAN.md`。

