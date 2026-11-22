# 插件运行时接入宿主命令（P2 集成报告）

本任务把已经完成、但尚未接线的三块能力接进宿主进程：

1. `internal/api`（33 条 REST 路由）与 `internal/agentapi`（7 条 `/agent/*` 路由）挂到
   standalone 控制器的 gateway 上；
2. `internal/pluginhost/supervisor` + `internal/pluginhost/hostsvc` + `internal/sandbox`
   组成的插件运行时，接到 `internal/operations` 的 `Dispatcher` 与宿主状态（journal、
   audit、secrets、operations）上；
3. `qwq serve-agent` 从占位实现换成真实装配（systemd 单元管理器、每插件 Host 通道、
   agent 生命周期）。

没有修改任何既有包的业务语义：`internal/api`、`internal/agentapi`、
`internal/{gateway,identity,authz,operations,catalog,events,secrets,tlsmgr,storage,
platform,doctor,sandbox,pluginhost/*}` 的代码一行未动，只新增导出方法/字段用于接线
（见 §2）。`go.mod`/`go.sum` 未改，无新依赖。

## 1. 文件

| 文件 | 状态 | 内容 |
|---|---|---|
| `internal/controller/plugin_runtime.go` | 新增（1588 行） | 全部适配器 + `PluginRuntime` 装配：`UnitManagerAdapter`、`PeerVerifier`、Host 服务工厂、六个 sink（Events/Config/Secrets/Audit/Invoke + Peer）、`pluginDispatcher`、`PluginDirResolver` |
| `internal/controller/controller.go` | 修改 | `Options.PluginRuntime`、`Controller.plugins`、`Close` 先停运行时、访问器 `Clock/IDs/Logger/PluginRuntime/HostDeps`、`operations.Options.Dispatcher` 接线 |
| `cmd/qwq/serve.go` | 修改 | `--plugins-dir`、构造/启动插件运行时、`registerPublicRoutes`（api + agentapi）、路由数日志 |
| `cmd/qwq/serve-agent.go` | 修改 | 真实 `sandbox.ExecSystemctl` + `UnitManagerAdapter` + Host 通道 + supervisor + agent；`--plugins-dir`/`--run-dir` |
| `internal/controller/plugin_runtime_test.go` | 新增（约 1350 行） | 适配器/映射/生命周期单测（24 个测试函数） |
| `cmd/qwq/serve_test.go` | 修改 | 43 条路由检查、运行时禁用规则、serve-agent 参数与 fake-units 装配测试 |

`internal/controller/controller.go` 的改动全部是新增：`Options` 多一个可选字段、
`Controller` 多一个私有字段和 5 个只读访问器、`Close` 多一步 `Stop`。没有改动任何已
有方法的语义。

## 2. 装配点

### 2.1 serve-controller（`cmd/qwq/serve.go`）

顺序（每一步失败都使启动失败）：

1. `config.Load` → logger → `signal.NotifyContext`；
2. `newPluginRuntime(cfg, --plugins-dir, logger)`：仅当 `cfg.Role == standalone` 且
   plugins 目录存在时构造 `*controller.PluginRuntime`；否则 `nil` + 一条
   `WARN/INFO`，不检测 root、不触碰 systemd；
3. `controller.New(..., controller.Options{PluginRuntime: rt})`：`operations.New` 拿到
   `rt.Dispatcher()`（`nil` 时 operations 对插件动作返回 `UNAVAILABLE`，这是既有行为）；
4. `rt.Start(ctx, c.HostDeps())`：绑定 DB/Ops/Secrets/Clock/Logger/NodeID 并启动
   supervisor；
5. `registerPublicRoutes(c, logger)`：
   ```go
   api.Register(c.Gateway(), api.Deps{Config, DB, Clock: c.Clock(), IDs: c.IDs(), Logger,
       Identity, Authz, Ops, Catalog, Secrets, TLS, NodeID: "local"})
   agentapi.Register(c.Gateway(), agentapi.Deps{DB, Clock, IDs, Logger, Identity, Authz,
       Ops, Catalog, NodeID: "local"})
   ```
   任一 `Register` 失败直接 `return 1`；成功则
   `logger.Info("routes registered", "routes", len(c.Gateway().Routes()), "plugin_runtime", rt != nil)`；
6. 之后才创建 `http.Server` / 监听。

`--plugins-dir` 默认 `/var/lib/qwq/plugins`；相对路径按用法错误退出 2。目录不存在只禁用
运行时并告警：空安装是合法状态，不能让服务起不来。

### 2.2 serve-agent（`cmd/qwq/serve-agent.go`）

- 加载同一份 bootstrap 文件；`--run-dir` 覆盖 `run_dir`（要求干净的绝对路径）；
- `controller.UnitManagerAdapter{Systemctl: sandbox.NewExecSystemctl(sandbox.ExecRunner{})}`；
- `newAgentRuntime(cfg, --plugins-dir, units, logger)` → `controller.NewPluginRuntime`，
  内部用 `agent.HostMux(rt.HostServer)` 作为 supervisor 的 Host（每个插件一个 host.sock）；
- `rt.Start(ctx, HostDeps{Clock, Logger, NodeID})`：agent 进程没有 DB，Host 通道保留
  State/Peer，journal/audit/config/secrets/invoke 按 `UNAVAILABLE` 处理；
- `supervisor.New` 已由 `NewPluginRuntime` 完成；随后 `agent.New{Supervisor: rt.Supervisor(),
  HostFactory: rt.HostServer}`、`a.Run(ctx)`（信号驱动，退出时 `sup.Close()`）。
- 配置校验未放宽：`role=agent` 仍被 `config.Validate` 拒绝，因此当前 agent 节点用
  `role=standalone` 配置运行；等拆分部署放开角色时无需再改本文件。plugins 目录缺失只
  WARN（仍可启动并等待后续安装）。

### 2.3 关闭顺序

`Controller.Close()` 第一件事是 `plugins.Stop()`（`supervisor.Close`：先取消 host channel
context、等待 hostsvc `GracefulStop`、关闭插件 gRPC 连接），然后才关 gateway、operations、
events hub、DB。因此 sink 不会在 DB 关闭后写库。`Stop` 幂等；`Start` 在 `Stop` 之后返回
`UNAVAILABLE`。

## 3. 适配器语义

### 3.1 `UnitManagerAdapter`（实现 `supervisor.UnitManager`）

- `sandbox.UnitNames(pluginID)` → `qwq-plugin@<id>.service`（socket 单元不使用），id 非法
  → `VALIDATION_FAILED`；`Systemctl == nil` → `UNAVAILABLE`；
- `Start/Stop/Kill` 直接转发；`Show` 把 `sandbox.UnitStatus` 转成 `supervisor.UnitState`，
  `StartTime` 来自 `ExecMainStartTimestamp`；
- 不缓存任何状态：`Show` 每次都问 systemd（P2-T1 结论：MainPID 会因带外重启失效）。
- NodeID 只用于日志标签，不参与策略。

### 3.2 `PeerVerifier`（生产 `hostsvc.PeerVerifier`）

`Verify(pid, uid)` 依序检查（任一失败返回 error，hostsvc 关闭连接，没有匿名回退）：

1. `pid > 0`，`uid != 0`（插件单元用 `DynamicUser=yes`，root 对端是接线错误）；
2. 期望 MainPID：先问 supervisor 实例（`SupervisorInstances`，返回 MainPID/Generation/
   Owner），没有实例时回退到 `systemd show` 的当前 MainPID（supervisor 在 `Host.Serve`
   之后才登记实例，插件可能在这个窗口内连上来；回退只用 systemd 事实）；
3. `pid == 期望 MainPID`；
4. 读 `/proc/<pid>/cgroup`，解析出 unit 名（兼容 unified 与 v1 的 `name=systemd`，并解码
   `\x2d` 转义），必须等于 `qwq-plugin@<id>.service`——这是“不是同组其他插件进程”的关键
   检查；
5. 若配置了 `ExpectedUID` 且解析成功，`uid` 必须相等；生产默认不配置（见 §6 占位 4），
   此时只跳过这一项，unit + MainPID + 非 root 仍然生效；
6. 成功时以 debug 记录 generation/owner。

`HostCallContext` 的任何字段都不参与判定；身份只来自内核（SO_PEERCRED）与 systemd。

### 3.3 Host 服务工厂

`PluginRuntime.HostServer(pluginID)` 返回 `hostChannel`，`Serve(ctx, pluginID)` 时：

- `hostsvc.New(hostsvc.Config{ PluginID, InstanceID: "default",
  SocketPath: supervisor.HostSocketPath(runDir, id), StateDir: <run>/state/<id>,
  Clock, Logger, State: nil（hostsvc 自带文件实现，落 <StateDir>/state.json 0600）,
  Events, Config, Secrets, Audit, Invoke, Peer, Limits: hostsvc.DefaultLimits() })`；
- 后台跑 `srv.Serve(ctx)`，并轮询 socket 出现（5 ms、上限 5 s）；Serve 提前返回则把错误
  交回 supervisor（避免“attach 成功但通道已死”）；
- 返回 stop：`srv.Close()` + 等待 Serve 返回（上限 5 s）。

### 3.4 EventSink

- `Publish`：`db.Update` + `tx.AppendEvent`；type = `<plugin>.<draft.Type>`，
  subject = `nodes/<node>/plugins/<id>/instances/default/<draft.Subject>`，
  schema_version 缺省 `"1"`，actor=`system/plugin:<id>`，node/operation/trace 来自
  host 事实；事件 ID 在同一事务里读回，返回 `EventRef{EventID, Sequence}`；
- `ReportChanges`：每个 change → `tx.Changed`，subject 加
  `nodes/<node>/plugins/<id>/instances/default/resources/` 前缀；`tx.SetOrigin` 带上调用
  方的 operation/trace，使 `resource.changed` 能按操作串联；revision 用 journal 序列
  （host 所有）；
- `Ack`：返回 nil（journal 才是可靠源；见 §6 占位 2）；
- delivery class：ABI 的 `EventDraft` 没有该字段，host 侧策略在
  `internal/events.Convert`，journal 事件一律 `reliable`，因此插件事件天然是可靠事件。

### 3.5 ConfigSource

P1 没有插件配置管理：`Current` 固定返回 revision `"0"` 和 `{}`。RPC 行为正确（插件拿到
空配置），但“已应用配置”是占位语义。

### 3.6 SecretRevealer

- 先 `operations.Get(system, operation_id)`，要求 operation 存在、`Status == RUNNING`、
  `Target.PluginID` 等于本插件、`Target.InstanceID` 为空或等于 `"default"`、node 匹配；
  任一不满足 → `hostsvc.ErrOperationNotDispatched`（FAILED_PRECONDITION）；
- 再 `secrets.Store.Reveal(ref, "plugin.config")`：purpose 是 `internal/secrets` 为插件引用
  记录的约定（`ExtractOptions{Purpose: "plugin.config"}`，schema.go 的注释与测试都用它）；
  purpose 不匹配、引用不存在、解密失败都统一返回 `hostsvc.ErrSecretDenied`
  （PERMISSION_DENIED），真实原因只进宿主 debug 日志；
- 成功后 `secret.Bytes()` 复制、`secret.Clear()` 擦除；审计由 hostsvc 在返回前写（fail
  closed），本层不重复写。

### 3.7 AuditSink

`operations.Audit` 写入审计：actor=`system/plugin:<id>`、source=`plugin`、subject 加
`nodes/<node>/plugins/<id>/instances/default/` 前缀；details 为
`{"host":{plugin_id,instance_id,action,operation_id,trace_id},"plugin":<插件原始 JSON>}`，
宿主字段不能被插件伪造，也不添加任何 secret 材料。`UNSPECIFIED` 结果按 `failure` 记录
（审计日志不能夸大成功）。

### 3.8 Invoker

- `InvokePlugin`：一律返回 `PERMISSION_DENIED` 域错误（gRPC 状态仍为 OK），不解析目标、
  不启动插件、不建 operation；capability 检查与子 operation 的正式方案见 ADR-0011（已接受，
  由 EXT-02 实施）；
- `WaitOperation`：先 `operations.Get(system, id)` 校验目标属于本实例（`owns`），通过后才
  `operations.Wait(system, id, timeout)`，再把状态/结果/错误/progress 填进
  `OperationSnapshot`；他人的 operation、未知 id、查询失败统一 `NOT_FOUND`；
- `CancelOperation`：同样先 `Get` + `owns`，通过后才经 `operations.Cancel`（以
  `plugin-cancel:<op>` 作幂等键，scope 是 caller principal），再返回观察到的状态；
- 调用方身份全部来自 `Config.PluginID`（listener 配置）与已校验的对端，不读
  `HostCallContext.instance_handle`。

### 3.9 Dispatcher（`operations.Dispatcher`）

`pluginDispatcher` 只做类型翻译，不碰事务、不做策略：

| operations | platformv1 | 备注 |
|---|---|---|
| `PluginPlanRequest` | `PlanOperationRequest` | Context: request/operation/trace/node/instance/locale/actor |
| `PluginInvokeRequest` | `InvokeRequest` | + `Preconditions`、`Attempt` |
| `PluginRunJobRequest` | `RunJobRequest` | + `Preconditions`、`Attempt`；progress 逐条回调 |
| `PluginCancelRequest` | `Client.Cancel(operationID)` | 只对已 attach 的实例（绝不 Ensure） |
| `Preview` | `PlanOperationResponse` | changes/violations/warnings/preconditions；未知 change kind 保留空串，让 operations 按“插件 bug”拒绝 |
| `PluginInvokeResponse` | `InvokeResponse` | result + changes |
| `JobProgress` | `JobProgress` | percent 0 → nil；`ErrorDetail` → `*problem.Error` |
| 错误 | `*problem.Error` | dispatcher 返回 `problem.From`，由 operations 统一记录/上报 |

`Plan/Invoke/RunJob` 先 `Ensure`（按需启动单元并 attach），`Cancel` 只查当前实例。所有调用
都在宿主写事务之外（operations 自身用“短事务包住调用”的既有模式）。

## 4. 路由注册

- `registerPublicRoutes` 在监听之前调用；两个 `Register` 的错误都直接上抛，`runServe`
  返回 1；
- gateway 自带 3 条（`/healthz`、`/readyz`、`GET /api/v1/events`）+ api 33 条 + agentapi
  7 条 = **43** 条；测试逐条检查无重复并断言关键路径存在。

## 5. 测试

构建机（`QWQ_REMOTE_SRC=integ1`，Linux，go1.27.3）实际执行：

```
gofmt -l internal/controller cmd/qwq                     # 无输出
go vet ./internal/controller ./cmd/qwq                   # 通过
staticcheck ./internal/controller ./cmd/qwq              # 通过
go build ./...                                           # 通过
CGO_ENABLED=1 go test -race -count=1 ./internal/controller ./cmd/qwq
    ok  github.com/qwq-panel/qwq/internal/controller   3.0s
    ok  github.com/qwq-panel/qwq/cmd/qwq               2.7s
CGO_ENABLED=1 go test -race -count=1 ./internal/api      # 通过（api 测试会构造 controller）
```

覆盖：

- `internal/controller`：`TestUnitManagerAdapter`（单元名、Show 映射、非法 id、未配置）、
  `TestUnitManagerAdapterPropagatesSystemctlError`、`TestCgroupUnit`/`TestReadCgroupUnit`、
  `TestPeerVerifier`（主进程、错误 pid、root、错误 uid、别的 unit、systemd 回退、无实例、
  无 cgroup）、`TestPluginDirResolver`（单版本/多版本/current/未安装/非法 id）、
  `TestHostEventSinkPublish`（type/subject/actor/schema 缺省）、
  `TestHostEventSinkReportChanges`（前缀、pointers、delete、operation 透传、空集合）、
  `TestHostConfigSource`、`TestHostSecretRevealer`（真实 secrets.Store：正确 purpose、
  错误 purpose、已删除引用、operation 归属/状态/节点、空 operation_id、未接线）、
  `TestHostAuditSink`（actor/source/subject/outcome/details 分层）、
  `TestPluginDispatcherPlan/Invoke/RunJob/Cancel`（请求与响应双向映射、错误透传、Cancel 不
  attach）、`TestHostInvokerRefusesPluginToPluginInvoke`（各类目标一律 `PERMISSION_DENIED`
  域错误、不 attach、不转发）、`TestHostInvokerWaitChecksOwnershipFirst/CancelChecksOwnershipFirst`
  （他插件/他实例/宿主 operation/未知 id/查询失败统一 NOT_FOUND，Wait/Cancel 一次都不调用）、
  `TestHostInvokerProtectsRealOperations`（真实 operations + 生产装配：插件不能等待或取消
  待审批的宿主 operation）、`TestHostInvokerWaitAndCancel`（快照/progress 映射、幂等键、
  归属通过后的错误透传）、`TestNewPluginRuntimeValidation`、
  `TestPluginRuntimeStartStop`（Start/Stop 幂等、Stop 后拒绝）、`TestPluginRuntimeHostServer`
  （未 Start 时拒绝、重复 id、非法 id）、`TestNewHostServiceConfig`（StateDir 创建）、
  `TestControllerStopsPluginRuntime`（Close 先停运行时、访问器、HostDeps）。
- `cmd/qwq`：`TestRegisterPublicRoutes`（43 条、无重复、关键路由）、
  `TestNewPluginRuntimeDisableRules`（缺目录 / 非 standalone / standalone）、
  `TestNewAgentRuntime`（fake `UnitManager`，构造 supervisor+host factory，绝不触碰
  systemd）、`TestServeAgentFlags`（缺配置、相对 `--run-dir`、相对 `--plugins-dir`）。

serve-agent 的测试用 fake `supervisor.UnitManager`，不安装单元、不执行 systemctl、不写
测试机的 `/run`。

## 6. 仍是占位 / 未覆盖

1. **配置管理**：`ConfigSource` 恒为 `{}`/revision 0；`plugin.config` purpose 的引用要等
   P3 的配置快照与 `ExtractSecrets` 接进来才真正产生。
2. **事件 Ack 不持久**：`EventSink.Ack` 是 no-op；hostsvc 的订阅游标只在内存，实现持久
   游标需要 storage 迁移（超出本任务写入范围）。
3. **ReportChanges 的 create/update 不可区分**：ABI 只给 `deleted` 与 revision，本层
   非删除一律记 `update`；等插件资源表/对象存储落地后再细分。
4. **uid 精确校验**：插件单元用 `DynamicUser=yes`，uid 由 systemd 每次分配，`systemctl
   show -p User` 只给用户名且动态用户解析依赖 NSS；生产默认不设置 `ExpectedUID`，只强制
   unit + MainPID + 非 root。`ExpectedUID` 钩子已留好，配置管理落地后可接
   `systemd` 的 `User`/`DynamicUser` 事实。
5. **插件安装与版本目录**：`PluginDirResolver` 按单元模板注释的布局
   `<dir>/<id>/<version>` 或 `<dir>/<id>/current` 解析；`qwq privileged install` 与安装器
   尚未接入（`internal/api` 的 install 仍返回 UNAVAILABLE），因此真实安装链路未测。
6. **真实 systemd**：环境里没有 systemd 单元/root，`UnitManagerAdapter`、
   `PeerVerifier` 的 `/proc`/systemctl 路径只做了单元级测试与代码审查；systemd 级联调
   需要真机（P2-T1 spike 的同类环境）。
7. **插件→插件调用的授权**：capability `plugin.invoke:<id>/<operation>` 检查与子 operation
   尚未实现，`InvokePlugin` 暂时一律拒绝（`PERMISSION_DENIED` 域错误），正式方案见
   ADR-0011。已知宽松点：Wait/Cancel 的 `owns` 仍按 operation 的 `target` 比较，即“派发给
   本实例”，比 ADR-0007 #5 的“本实例创建”宽，插件仍可等待或取消派发给自己的 operation；
   ADR-0011 §6 收紧。
8. **跨节点**：`InvokePlugin` 一律拒绝（见第 7 条），非本节点的目标也不例外；节点网关/
   转发不在本任务。
9. **`subscriptions` 的事件回放**：hostsvc `SubscribeEvents` 只服务本地缓冲，宿主没有把
   journal 事件 `Ingest` 进去；UI 走 `GET /api/v1/events`（journal），插件订阅只有实时
   部分。接线点已存在（`hostsvc.Server.Ingest`），但没有事件路由组件。

## 7. 风险

1. **Peer 验证窗口**：supervisor 在 `Host.Serve` 之后才登记实例，回退路径会调用
   systemd；若 systemd 短暂不可用，插件首次连接会被拒绝（fail closed），重连后恢复。
2. **每个 attach 的额外 systemctl 调用**：仅在“实例尚未登记”的窗口发生，且 3 s 超时。
3. **hostsvc 审计配额与 secret reveal 共享**：插件可以刷 audit 让自己的 reveal 被限流
   （hostsvc 已声明的 fail-closed 取舍），集成层未改动。
4. **runtime 只按“目录存在”启用**：不检测 systemd/polkit，容器/开发机上若手工创建了
   plugins 目录，插件操作会以 `PLUGIN_UNAVAILABLE` 失败（不会误报成功）。
5. **`serve-agent` 与 controller 同进程独享 `run_dir`**：两者不应同时对一个 `run_dir`
   服务插件（hostsvc 状态文件单写者假设）；部署文档需说明。
6. **`Invoker` 的 Cancel 幂等键**：`plugin-cancel:<op>` 每个 operation 一个键，长期运行
   会在 `idempotency_keys` 留下记录，由既有 TTL 清理。
7. **`ReportChanges` 每个 change 一次 `tx.Changed`**：受 hostsvc `MaxChanges`（256）约束，
   但一次 256 条会放大写事务；如成为热点应在 operations 侧批量。

## 8. 参考

- `internal/pluginhost/supervisor/REPORT.md`（单元、generation、宿主通道约定）
- `internal/pluginhost/hostsvc/REPORT.md` §5（peer 校验目标语义）、§9（capability 缺口）
- `internal/sandbox/REPORT.md`（单元模板、polkit、`UnitNames`）
- `deployments/systemd/qwq-plugin@.service`（DynamicUser、Host sock 路径、KillMode）
- `api/qwq/platform/v1/platform.proto`（Host 六个服务、`ErrorDetail`、`JobProgress`）
- ADR-0003（传递与身份）、ADR-0004 D3/D7、ADR-0007（错误与 capability）、ADR-0008 §1/§3
