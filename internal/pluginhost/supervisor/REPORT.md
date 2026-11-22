<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# P2-T7：Supervisor + Agent 骨架报告

- 日期：2026-11-01
- 范围：`internal/pluginhost/supervisor/**`（新包）、`internal/agent/**`（新包）、`cmd/qwq/serve-agent.go`（新文件）、根 `go.mod`/`go.sum`
- 依据：ADR-0003（方案 A）、`spikes/p2t1/REPORT.md` §5/§6/§9、ARCH §6.4/§6.6/§10.2

## 1. 文件

| 文件 | 内容 |
|---|---|
| `supervisor/doc.go` | 包说明与边界（不依赖 systemd/sandbox/hostsvc 实现） |
| `supervisor/supervisor.go` | `UnitManager`/`HostServer`/`Options`/`New`/`Start`/`Ensure`/`Stop`/`Kill`/`Cleanup`/`Instances`/`Client`/`Close`；Reattach、退避、generation、degraded |
| `supervisor/instance.go` | `Instance`、`Status`、`generation`=sha256(unit\|MainPID\|starttime)[:16]、`Owner` |
| `supervisor/client.go` | `Client`：`Plan`/`Invoke`/`RunJob`/`Cancel`，gRPC→problem 映射 |
| `supervisor/logs.go` | `AttachLogs`：每插件行/字节限速、长行截断、结构化日志 |
| `supervisor/limits.go` | `Limits`/`UnitResources`/`LimitsFor`/`Validate`（MemoryHigh 0.9×、GOMEMLIMIT 0.85×） |
| `agent/agent.go` + `agent/host.go` | `Options`/`New`/`Run`（Start supervisor、SIGTERM/SIGINT、Close）；`HostMux` 把 per-plugin `HostFactory` 适配成单个 `HostServer` |
| `cmd/qwq/serve-agent.go` | `runServeAgent`、`--config`、占位 Units/Host（UNAVAILABLE）；未改 `main.go` |

## 2. 导出 API

```go
// supervisor
func New(Options) (*Supervisor, error)
func (s *Supervisor) Start(ctx context.Context) error
func (s *Supervisor) Ensure(ctx context.Context, pluginID string) (*Instance, error)
func (s *Supervisor) Stop(ctx context.Context, pluginID string) error
func (s *Supervisor) Kill(ctx context.Context, pluginID string) error
func (s *Supervisor) Cleanup(owner string)                       // 幂等；不 stop unit
func (s *Supervisor) RegisterCleanup(owner string, fn func())    // 额外的宿主侧登记
func (s *Supervisor) Instances() []Status
func (s *Supervisor) Client(pluginID string) (*Client, error)
func (s *Supervisor) Close()
func (s *Supervisor) AttachLogs(pluginID, stream string, r io.Reader) (detach func())
func UnitName(pluginID string) string
func SocketPath(runDir, pluginID string) string
func HostSocketPath(runDir, pluginID string) string
func Owner(pluginID, generation string) string
func LimitsFor(UnitResources) (Limits, error)
func PluginDialOptions() []grpc.DialOption              // 宿主每个 plugin.ClientConfig 的 GRPCDialOptions
const MaxPluginMessageBytes = 4<<20 + 256<<10            // 宿主↔插件单条 gRPC 消息上限

type UnitState struct{ MainPID int; ControlGroup, ActiveState, SubState string; StartTime time.Time }
type UnitManager interface {
    Start(ctx, pluginID) error; Stop(ctx, pluginID) error; Kill(ctx, pluginID) error
    Show(ctx, pluginID) (UnitState, error)
}
type HostServer interface{ Serve(ctx, pluginID) (stop func(), err error) }
type Options struct { // 必填
    Units UnitManager; Host HostServer; PluginDir func(string) (string, error)
    // Clock, Logger, NodeID, MaxRestarts, BackoffMin/Max, LogLinesPerSecond；本次可选补充：LogBytesPerSecond, RunDir, ConnectTimeout, Limits
}
type Status struct { /* PluginID, Unit, Generation, Owner, MainPID, ActiveState, SubState, ControlGroup, State, VersionDir, HostServing, Attempts, Since, LastError, RetryAt */ }

// Instance：PluginID/Unit/Generation/Owner/MainPID/VersionDir/Since/HostServing/Limits/Client
// Client：Plan(ctx,*PlanOperationRequest)、Invoke(ctx,*InvokeRequest)、
//         RunJob(ctx,*RunJobRequest,func(*platformv1.JobProgress) error)、Cancel(ctx,operationID)

// agent
func New(Options) (*Agent, error); func (a *Agent) Run(ctx context.Context) error
func (a *Agent) HostServer() supervisor.HostServer
func HostMux(func(pluginID string) (supervisor.HostServer, error)) supervisor.HostServer
```

## 3. go-plugin 用法、版本与许可证

- `github.com/hashicorp/go-plugin v1.8.0`，**MPL-2.0**（文件级 copyleft）。只链接/调用、不复制源码，MPL-2.0 §3.3 允许把 Larger Work 以 AGPL-3.0-only 分发，二者兼容。
- `go.mod`：把 go-plugin 加入第一个（直接）require 块；`GOWORK=off go mod tidy` 收敛后新增的间接依赖只有它自己的依赖（`go-hclog v1.6.3`、`yamux v0.1.2`、`oklog/run v1.1.0`、`fatih/color`、`mattn/go-colorable`、`golang/protobuf`）。**没有加入其它依赖**；`go.sum` 新增对应条目。
- 连接方式（唯一路径，首次启动与宿主重启恢复相同）：

```go
client := plugin.NewClient(&plugin.ClientConfig{
    Reattach: &plugin.ReattachConfig{
        Protocol: plugin.ProtocolGRPC,
        Addr:     &net.UnixAddr{Name: socketPath, Net: "unix"},
        Pid:      mainPID, // 只供 go-plugin 等进程退出；不参与身份判断
    },
    AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
    GRPCDialOptions:  PluginDialOptions(), // 收发上限 MaxPluginMessageBytes
})
proto, err := client.Client()          // Reattach 会先 net.Dial 探活
gc := proto.(*plugin.GRPCClient); gc.Conn // platformv1.NewPluginServiceClient(conn)
```

- 消息上限：go-plugin v1.8.0 的 `dialGRPCConn` 先把收发上限设为 `math.MaxInt32`，再追加 `GRPCDialOptions`；CallOption 后设置者生效，所以 `PluginDialOptions()` 把宿主侧上限收紧到 `MaxPluginMessageBytes`（4 MiB 载荷 + 256 KiB 余量）。超限的插件响应以 `ResourceExhausted` 失败，不会被宿主整条缓冲。controller 的 `UpdaterRuntime` 用同一组选项；插件侧（SDK-08）必须用同一个值。

- 明确**未使用**：`plugin.Serve`、`AutoMTLS`、`SecureConfig`、`GRPCBrokerMultiplex`、`Client.Kill()`、`Managed`。关闭只调 `GRPCClient.Close()`（关连接与 broker，不发信号）；停/杀走 `Units.Stop/Kill`。
- 连接成功判据是**传输层 READY**（HTTP/2 握手完成，不调用任何插件 RPC），所以只实现了部分 RPC 的插件也能 attach。
- 已知 go-plugin 行为（spike §6.2/§6.3 的延续）：每次 attach 会启动 broker/stdio 客户端与一个 `pidWait` goroutine；插件没实现 stdio/controller 时只在 stderr 打 debug 行（不失败）。`pidWait` 只能等进程退出（没有不 Kill 的 detach API），因此每次 generation 变更留 1 个 goroutine，量级与重启次数相同。要把它接到 slog 需要把 go-hclog 变成直接依赖，本次任务不允许。

## 4. 生命周期语义

- **generation** = `sha256(unit|MainPID|starttime)[:16]`；`starttime` 取 `UnitState.StartTime`（适配层必须返回 systemd 的 `ExecMainStartTimestamp`）。`Ensure` 每次都 `Units.Show`，不缓存 MainPID：相同 generation 且连接未坏 → 复用；否则先丢弃旧实例（停 host server、关连接、`Cleanup(owner)`）再重连。带外重启后旧 `Client` 的每次调用返回 `PLUGIN_UNAVAILABLE`。
- **attach 顺序**：`PluginDir`（只读）→ `Limits` 校验（无副作用，非法 manifest 不会启动 unit）→ `Show` → `MainPID==0` 时 `Start` → 再 `Show`（仍为 0 则失败）→ 算 generation → Reattach → gRPC READY → `Host.Serve` → 登记实例。任何一步失败都会关掉已建的连接，不留下半成品实例。
- **重连/退避**：一次 `Ensure` 最多 `MaxRestarts` 次尝试（默认 3，含第一次）；第 n 次重试等待 `min(BackoffMax, BackoffMin·2^(n-1))`，抖动区间 `[d/2, d)`；默认 1s→…→5min；等待用 `Clock.After` 且可被 ctx 取消。预算耗尽 → `degraded`，`RetryAt = now + BackoffMax`；冷却期内的 `Ensure` 直接返回 `PLUGIN_UNAVAILABLE`，不碰 unit、不轮询；冷却后自动重试。成功 attach 清除 degraded。
- **连接损坏**：gRPC `Unavailable` 把实例标记 broken，下一次 `Ensure` 即使 generation 未变也会重连（不覆盖插件自身返回的业务错误）。
- **Stop/Kill**：先 `Units.Stop/Kill`，再丢本地实例；即使 systemd 命令报错也丢（避免藏住死实例）；返回 `PLUGIN_UNAVAILABLE` 并保留 cause。**绝不**向进程发信号，cgroup 清理由 systemd 负责。
- **Cleanup(owner)**：`owner = pluginID@generation`（也接受裸 pluginID，表示当前实例）。执行并移除该 owner 的登记回调（幂等）、若仍是当前实例则停 host server/关连接，但**不 stop unit**；旧 generation 的 owner 对当前实例无影响。
- **Close**：置 closed → 取消 lifetime ctx → 停日志泵（最多等 5s）→ 逐插件丢实例（关 host server/连接）→ 运行剩余登记回调；可重复调用；不杀插件进程。
- **并发**：每插件一把 `sync.Mutex`（map 只由短临界区保护）；不持锁做网络调用；`Instance` 自身状态另有小锁；`Instances()` 只在快照时短暂持锁。
- **日志**（`AttachLogs`）：每插件的行/字节预算跨流共享，1s 窗口；超限丢弃并计数，下一窗口写一条 `plugin output was rate limited` 汇总；单行截断到 8 KiB；结构化字段 `plugin_id/generation/stream/line/truncated`。只读、不作为协议通道；宿主负责关闭 reader（`detach`/`Close` 会等待，Close 上限 5s）。
- **资源**：`Limits` 只做派生与校验（内存 16–65536 MiB，CPU/PIDs/FDs 与 manifest 一致），`UnitManager` 负责写 `MemoryMax/MemoryHigh/OOMScoreAdjust/CPUQuota/TasksMax/LimitNOFILE` 与 `GOMEMLIMIT`。

## 5. RunJob 流语义（ADR-0007 #15）

| 情况 | 交给 progress 的消息 | 返回值 |
|---|---|---|
| 普通进度 | 1 条 | 继续 |
| `completed=true` 且无 error | 该终止消息（**恰好一条**，随后立即返回，不等插件关流） | nil |
| 终止消息带 `error` | 该终止消息 | `problem.FromPlugin`（保留 code/retryable/violations） |
| progress 回调返回错误 | 不再交付 | 原样返回，并取消插件流 |
| 流结束/中断且无终止消息 | 0 条终止 | `PLUGIN_UNAVAILABLE` |
| ctx 取消/超时 | 0 条终止 | `UNAVAILABLE`/`TIMEOUT` |
| 同一实例重复 operation_id | — | `VALIDATION_FAILED` |
| 旧 generation 的 Client | — | `PLUGIN_UNAVAILABLE` |

`Cancel(ctx, operationID)` 取消该流 context（ABI v1 没有取消 RPC）；未知 operation 返回 nil（best effort）。

## 6. 测试命令与结果

```text
CGO_ENABLED=1 GOWORK=off go test -race -count=3 ./internal/pluginhost/supervisor/... ./internal/agent/...
ok  github.com/qwq-panel/qwq/internal/pluginhost/supervisor  1.573s
ok  github.com/qwq-panel/qwq/internal/agent                  1.109s

CGO_ENABLED=1 GOWORK=off go test -race -count=2 ./internal/pluginhost/supervisor/... ./internal/agent/... ./cmd/qwq/...
ok  .../supervisor  ok  .../agent  ok  github.com/qwq-panel/qwq/cmd/qwq  3.640s

CGO_ENABLED=1 GOWORK=off go test -cover ./internal/pluginhost/supervisor/... ./internal/agent/...
coverage: 82.4% of statements (supervisor), 89.6% (agent)

gofmt -l <三个包/文件>   # 空
GOWORK=off go vet ./internal/pluginhost/supervisor/... ./internal/agent/... ./cmd/qwq/...
GOWORK=off staticcheck <同上>   # 无输出
```

测试矩阵（40 个用例全 PASS，0 FAIL）：Ensure 冷启动（Show→Start→Reattach、Status/Client 身份）；同 generation 复用；带外重启（fake Show 改 MainPID/StartTime）使旧实例失效且清 owner；退避次数、degraded 冷却与恢复；连接损坏后重连；Stop/Kill 只调 UnitManager（Reattach 的 Pid 是测试进程本身，若调用了 `Client.Kill` 测试进程会被 SIGKILL）；host server 启停与 `Cleanup` 幂等/旧 owner 隔离；`Close` 关连接但不 stop unit；Plan/Invoke 的 ErrorDetail 与 gRPC 状态映射；RunJob 成功终止、错误终止、无终止结束、ctx 取消、`Cancel`、回调错误中止、重复 operation、旧 generation；日志行限速与窗口汇总、超长行截断、非法 plugin id；Limits 派生/边界；Agent 的构造校验、Run 启停与 HostMux 委托/失败。未安装任何 systemd 单元、未接触测试机。

## 7. 需要主会话适配的接口

1. **sandbox → `UnitManager`**：`Start/Stop/Kill` = `systemctl start/stop/kill`（强杀用 `--kill-whom=main`，配合 `KillMode=control-group`）；`Show` = `systemctl show -p MainPID,ControlGroup,ActiveState,SubState,ExecMainStartTimestamp`，**不得缓存**；`Start` 返回后紧跟的 `Show` 必须已能给出 MainPID；按 `Limits` 渲染 drop-in。`StartTime` 用 `ExecMainStartTimestamp`；若适配层还能读 `/proc/<pid>/stat` 第 22 字段，一并折进该时间戳可进一步消除 PID 复用窗口。
2. **hostsvc → `HostServer`**：在 `supervisor.HostSocketPath(runDir, id)` 监听（0660、组 `qwq-p-<id>`），用 `SO_PEERCRED` 证实 `pid==MainPID`、cgroup 单元名，并按 `Instance.Generation()`/`Owner()` 校验；`stop` 必须撤销该 owner 的全部登记（路由、订阅、定时器、任务、授权），长期登记可用 `Supervisor.RegisterCleanup`。当前 hostsvc 的形态是 `New(Config)` + 阻塞的 `Serve(ctx)` + `Close()`，适配层把它包成 `HostServer.Serve(ctx, pluginID) (stop, error)`（goroutine 起 `Serve`，`stop` 里 `Close`）；`Generation/MainPID/Owner` 已由 supervisor 提供，peercred 校验本身不在本包。
3. **operations → `Client`**：把 `PluginPlanRequest/PluginInvokeRequest/PluginRunJobRequest/PluginCancelRequest` 映射成 proto；`JobProgress` 反序列化 `Changes`，`ErrorDetail` → `*problem.Error`；`CancelOperation` 用 `Client.Cancel(ctx, operationID)`；本包错误都是 `*problem.Error`（PLUGIN_UNAVAILABLE/TIMEOUT/PLUGIN_ERROR/VALIDATION_FAILED…）。
4. **`cmd/qwq/main.go`**：加 `case "serve-agent": return runServeAgent(args[1:], stdout, stderr)` 与 usage 行（主会话已加）。
5. **`platform/config`**：`role: "agent"` 目前被 `config.Validate` 拒绝（"not available in this release"）；`serve-agent` 需要放开（不在本任务写入范围）。
6. **宿主接入**：supervisor 不启动 `journalctl`，由宿主把插件 stdout/stderr 的 reader 交给 `AttachLogs` 并在 detach/Close 前关闭；`Options` 的 `NodeID`、`RunDir=cfg.RunDir`、`Clock/Logger`、`MaxRestarts/Backoff*`、`Limits`（`UnitResources{MemoryMaxMB,CPUQuotaPercent,PIDsMax,FDsMax}`）由宿主装配。

## 8. 已知限制与风险

- Reattach 的 `pidWait` goroutine 无法在 go-plugin 内停止（除非 Kill），每次 generation 变更留 1 个（量级等于重启次数，插件退出后结束）；go-plugin 默认 hclog logger 会把 broker/stdio 的 trace/debug 行写到进程 stderr，接 slog 需要直接依赖 go-hclog（本次禁止）。
- generation 依赖 systemd StartTime（适配层返回零值时只剩 MainPID 作为变化信号，PID 复用检测变弱）；每次 `Ensure` 1–2 次 `systemctl show`（开销可忽略），`Instances()` 是最近一次 attach 的快照而非实时 systemd 状态。
- SO_PEERCRED/cgroup 名校验属于 hostsvc；本包只提供事实（Owner/Generation/MainPID/Unit）与清理语义。
- 未做真实 systemd 集成测试（任务要求不碰测试机），也未有蓝绿双实例并发场景；离线/无 polkit 的降级由 sandbox 适配层与 `qwq doctor` 负责。
