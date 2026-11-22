# P3-T3：updater 安装器 / systemd + go-plugin 运行时适配（restart-only）

## 1. 文件与导出面

新增 `internal/controller/updater_runtime.go`：
- `PluginInstaller`：`updater.Installer`（Stage / InstallUnit / RemoveUnit）。
- `UpdaterRuntime`：`updater.Runtime`（Start/Attach/Ready/Activate/Deactivate/Stop/Release/
  Health/ValidateConfig/ApplyConfig/SwapRoutes + `Routes()`）。
- `HostMemory`：`updater.MemorySource`（MemAvailable + cgroup v2 `memory.current`）。
- `(*Controller).UpdatePlugin`：强制 `updater.StrategyRestart` 的更新入口。
- `DefaultStagingDirName = ".staging"`。新增 `updater_runtime_test.go`。

修改：`internal/controller/controller.go`（`Options.Updater`、原子 `Updater()`/`SetUpdater()`，
`Close` 不关闭 updater）；`cmd/qwq/serve.go`（`--trust-dir` 默认 `/etc/qwq/trust`、`newUpdater`、
`Recover`、staging 清理）；`internal/pluginhost/supervisor/client.go`（追加 `GetDescriptor`、
`Initialize`、`Start`、`Activate`、`Deactivate`、`Stop`、`ReleaseInstance`、`CheckHealth`、
`ValidateConfig`、`ApplyConfig`，全部复用 `service()` 的 generation 校验与
`rpcError`/`fromErrorDetail`）；`supervisor/client_test.go`。

**命名偏差**：`controller.PluginRuntime` 已被 P2 占用，P3 运行时只能叫 `UpdaterRuntime`；
`PluginInstaller` 与任务一致。

## 2. PluginInstaller 语义

- `Stage`：每次调用重新读 `TrustDir/*.pem`（`pkgfile.ParsePublicKeyPEM`）并
  `manifest.NewStaticTrustStore`；目录缺失/不可读/无 `*.pem`/密钥非法/重复 → `UNAVAILABLE`
  （运维问题，不是请求问题）。随后 `install.Extract(ctx, pkgPath, trust, StagingRoot)`：
  签名 → 严格 manifest → 逐文件 digest 全通过才产生 staging 目录。返回
  `updater.Staged{PluginID, Version, Digest, Manifest, ManifestJSON, Handle, Discard}`；
  Digest=`sha256(manifest 原始字节)`（与 updater.digestOf 一致），ManifestJSON 是签名覆盖的
  原始字节，Handle 是 `*install.Staged`。
- `InstallUnit`：只接受 `*install.Staged`；`HostBinary` 非空且不等于
  `sandbox.DefaultHostBinary` 时拒绝（unit 模板写死宿主二进制）。`VersionDir=install.VersionDir`；
  不存在则 `Commit`（单次 rename、不可变），已存在则视为“已发布”，只 Discard 新 staging、
  不覆盖——同一 `Staged` 重复调用或重新 Stage 同版本再调用都成功（恢复可重试）。`UnitSpec`
  取自 manifest：ID/VersionDir/Entrypoint/`Digest=Files[entrypoint]`/`Executable`/
  `Limits=resources.*`；`Sandbox.Install(ctx, spec, nil)` 原子写 unit/socket/drop-in/tmpfiles。
  重写 unit 不影响运行中的旧进程（saga 在 install 之后才 stopOld）。
- `RemoveUnit`：先 `systemctl show`，`MainPID>0` → `PRECONDITION_FAILED`（unit 名按插件而非
  版本）。仅当 `<PluginsRoot>/<id>/` 下没有其它版本目录时才 `sandbox.Installer.Remove`
  （unit/tmpfiles/runtime/credential/group）；保留版本仍需要 unit 供后续启动/回滚。最后
  “先 chmod 再 RemoveAll”删只读版本目录并清理空插件目录；整体幂等。
- `Sandbox` 是 `sandbox.Installer` 值（serve 用 `DefaultInstaller(ExecRunner{})`）；测试用
  临时 UnitDir/TmpfilesDir/RuntimeBase + 记录型 Runner，不碰 systemd/root。

## 3. UpdaterRuntime 语义

- `Start`：校验 spec（id≤26、version 语法、manifest 非空）→ 版本目录存在 → 注册表无 live
  实例 → `show` 确认 MainPID==0（否则 `PRECONDITION_FAILED`）→ `systemctl start
  qwq-plugin@<id>.service` → `show` 取 MainPID/ExecMainStartTimestamp → go-plugin
  `ReattachConfig{ProtocolGRPC, UnixAddr(<runDir>/plugin/<id>/plugin.sock), Pid:MainPID}`（
  `GRPCDialOptions: supervisor.PluginDialOptions()`，单条消息上限 4 MiB + 256 KiB）→
  `*plugin.GRPCClient` → `platformv1.NewPluginServiceClient(conn)`；返回不透明
  `*pluginHandle`（ID/Version/MainPID/StartTime/generation/owner/client/conn）。attach 失败时
  best-effort stop（失败再 `systemctl kill --kill-whom=main`），避免坏候选占住 unit 让回滚起
  不来。attach 后用 `GetDescriptor` 比对 `plugin_version` 与 spec.Version（UNIMPLEMENTED 接受）：
  ExecStart 按版本写死，daemon-reload 前 systemd 仍用旧定义；发现实际是旧版本 →
  `PLUGIN_UNAVAILABLE` + 停 unit，绝不把旧进程记成新版本。**从不**
  `plugin.Serve`/AutoMTLS/SecureConfig/`Client.Kill`；generation 与 P2 相同，owner 用
  `supervisor.Owner`。
- `Attach`：只 `show`；MainPID==0 → `PLUGIN_UNAVAILABLE`；不 start/stop/kill；同
  plugin+version 已有 live handle 时复用连接（Recover 用）。
- `Ready`/`Health`：`CheckHealth`；传输失败或状态非 `SERVING` → `PLUGIN_UNAVAILABLE`。
- `Activate`/`Deactivate`：转发（ABI 幂等）；Deactivate 对已停止/已释放实例返回 nil。
- `Stop`：先 `Stop{drain:true, grace_period_ms}`（超时=grace+1s，失败仅告警），再
  `systemctl stop`；失败则用脱离调用方 deadline 的 10s 上下文 `systemctl kill
  --kill-whom=main`。两步都失败才 `PLUGIN_UNAVAILABLE`。成功才标记 stopped（失败可重试）；
  幂等，不关连接。
- `Release`：`*plugin.GRPCClient.Close()`（非 Kill）+ 清 registry；幂等、返回 nil。
- `ValidateConfig`：带 proposed/current revision（handle 记录上次 Apply）；插件 Error 原样
  映射；仅 violations → `VALIDATION_FAILED` 并携带 pointer/code/message。
- `ApplyConfig`：Error 原映射；`applied_revision != proposed` → `PLUGIN_ERROR`；成功才更新
  handle 的 revision。
- `SwapRoutes`：`atomic.Pointer[*updater.RouteTable]` 存不可变快照（nil 归一为空表）；
  `Routes()` 读取。只存快照：operations Dispatcher 仍走 P2，P3 路由切换留主会话。
- 内部 `map[pluginID]map[version]*pluginHandle` + mutex；released 从 map 清理；Handle 即
  `*pluginHandle`（满足 `updater.Handle` 空接口）。

## 4. restart-only 限制

- unit 名按插件而非版本，两个版本不能同时拥有 unit，overlap 无法表达。
- `(*Controller).UpdatePlugin` 无条件改为 `StrategyRestart`；P3-T4 更新端点必须走它。
- `Start` 只要该插件还有 live 实例（注册表或 systemd MainPID）就 `PRECONDITION_FAILED`；
  restart 顺序保证调用时旧版已停。`Install` 走 `StrategyInstall`，兼容。
- **Rollback 缺口**：① `updater.Rollback` 无 strategy 参数，`planMemory` 可能选 overlap
  （`overlap_safe=true` 且内存足）；P3-T3 未接 rollback，主会话须加强制 restart 或上层 gate。
  ② update 的 install 已把 unit 改写成候选版，`updater.restoreOld` 只 Attach/Start、不重渲染
  旧 unit，失败回滚会指向候选版；GetDescriptor 校验让它显式失败而非误记成功，但旧版起不来。
  修复需稳定 per-plugin ExecStart（`current` 符号链接）或回滚时重渲染 + daemon-reload。

## 5. trust 与凭据

- 信任根 `/etc/qwq/trust/*.pem`（`--trust-dir` 覆盖），每次 Stage 重新加载；无密钥 →
  `PluginInstaller.Stage` 返回 `UNAVAILABLE`。注意 `updater.stage()` 会把 installer 错误统一
  重包为 `INTERNAL`，HTTP 层目前看到 INTERNAL；T4 要 503 需预检或放宽 updater.stage。
- **插件 token 未接线**：`InstallUnit` 传 `credential=nil`；unit 有
  `LoadCredential=qwq-token:%t/qwq/creds/%i.token`，首次 start 会因凭据缺失失败。
  `sandbox.Installer` 在 nil 时不删除已有 token，重装可保留；但 P1–P3 无 token API，
  需主会话补 provisioning。

## 6. controller / serve 接线

- `Options.Updater` + `SetUpdater`：updater 需要已迁移的 DB，而 DB 在 `controller.New` 内
  打开，所以 serve 在 `New` 后构造并 `SetUpdater`；`Options.Updater` 留给已有 updater 的
  调用方/测试。`Close` 不关闭 updater。
- serve 顺序：`controller.New` → `rt.Start(c.HostDeps())` → `newUpdater`（必须先 bound P2，
  Recover 附着的插件才有 host channel）→ `SetUpdater` → `Recover` → 注册路由 → 监听。
- 启用条件：standalone、插件运行时非 nil、`--plugins-dir` 与 `--trust-dir` 都存在；目录缺失
  → WARN 并禁用（合法安装）。`updater.New` 失败 → 启动失败；`Recover` 出错 → ERROR 后继续
  （坏 saga 已被 updater 标记 FAILED，不应让宿主起不来）。
- staging=`<plugins-dir>/.staging`（同文件系统），启动时 `install.CleanupStale(…, 1h)`；
  `serve-agent` 未改。

## 7. 测试与门禁

```
gofmt -l <changed files>                 # 无输出
go build ./...
go vet ./internal/controller/... ./internal/pluginhost/supervisor/... ./cmd/qwq/...
staticcheck ./internal/controller/... ./internal/pluginhost/supervisor/... ./cmd/qwq/
CGO_ENABLED=1 go test -count=1 -race ./internal/controller/... ./internal/pluginhost/supervisor/... ./cmd/qwq/...
  ok internal/controller 4.0s / ok internal/pluginhost/supervisor 1.3s / ok cmd/qwq 2.8s
```

覆盖：两层生命周期转发（supervisor Client / UpdaterRuntime）、generation 失效、断连映射、
Ready/Health 的 SERVING 判定、Validate/Apply revision、Stop 的 drain→stop→失败才 kill
（成功路径 kill==0，从不调用 go-plugin Kill）、Stop/Release 幂等、Release 后不可用、Attach
不启停、Start 的 FAILED_PRECONDITION、坏 spec/坏 systemd/缺版本目录、Start 失败清理 unit、
GetDescriptor 版本不符、Routes 快照、HostMemory、installer 的签名/摘要/路径/重复安装/保留
版本时保留 unit/无信任密钥 → UNAVAILABLE。未安装 systemd、未用 root、未碰测试机。

## 8. 需要主会话接的点

1. **HTTP 安装/更新端点（P3-T4）**：更新走 `c.UpdatePlugin`；安装走 `c.Updater().Install`；
   Rollback 先解决第 4 节两个缺口。
2. **路由切换**：`UpdaterRuntime.Routes()` 是快照，Dispatcher 仍是 P2；把 operation dispatch
   指向 P3 路由留给主会话。
3. **Initialize + Start RPC**：`InstanceSpec` 没有 config/instance_handle，`Start` 只做进程
   启动 + attach，不调插件 `Initialize`/`Start`；严格 ABI 插件会在 CheckHealth 返回
   NOT_SERVING。需扩展 InstanceSpec 或约定由别的层 Initialize。
4. **插件 token**：见第 5 节。
5. **双连接**：P2 supervisor 与 P3 `UpdaterRuntime` 各建一条 go-plugin 连接（gRPC 支持）；
   host channel 仍由 P2 提供。需真实空插件端到端确认。
6. **daemon-reload（必须处理）**：unit 的 ExecStart/ExecStartPre 按版本渲染，systemd 只有
   `daemon-reload` 后才读改写后的 unit；`sandbox.Installer`、`qwq privileged install` 都不做，
   agent polkit 也只允许 manage-units 的 start/stop/restart/reload/kill（不含 reload-daemon）。
   更新 stop→start 可能仍启动旧 ExecStart；GetDescriptor 校验会显式失败而非误记成功，正确
   修复是特权 helper 写 unit 后以 root daemon-reload，或稳定 ExecStart + 版本符号链接。
