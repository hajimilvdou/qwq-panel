# P3 事务式插件热更新（`internal/pluginhost/updater`）

状态：实现完成，单元测试（真实 SQLite + fake Runtime/Installer/Memory）通过。
范围：`internal/pluginhost/updater/**`、`internal/storage/migrations/0006_plugins.sql`。
未改 `go.mod`、`api/`、`docs/`、`scripts/`、其他 `internal/**` 现有文件。

## 1. 文件

| 文件 | 内容 |
|---|---|
| `migrations/0006_plugins.sql` | 版本、配置快照、更新 saga 三张表与索引 |
| `updater/doc.go` | 包文档：为什么是 saga、两种策略、事务边界 |
| `updater/runtime.go` | `Runtime` / `MemorySource` / `Installer` / `Staged` / `InstanceSpec` |
| `updater/types.go` | 版本状态、策略、saga 状态、请求/结果、不可变 `RouteTable` |
| `updater/options.go` | `Options`、`New`、状态加载、句柄表、按插件锁、路由发布 |
| `updater/store.go` | 只读查询与行扫描 |
| `updater/version.go` | 状态机、版本行写入、`tx.Changed`、审计事件 |
| `updater/saga.go` | 步骤顺序、逐步骤执行、失败回滚、提交、crash 恢复规则 |
| `updater/update.go` | `Install` / `Update` / `Rollback`、能力确认、saga 创建 |
| `updater/recover.go` | `Recover`、未完成 saga 计划重建、不可恢复标记 |
| `updater/config.go` | 配置候选 → 校验 → 应用 → 切换指针、保留策略 |
| `updater/memory.go` | 小内存 preflight |
| `*_test.go` | 40 个测试，含每步骤 kill 注入、路由 race、并发串行化 |

## 2. 迁移 0006（STRICT）

- `plugin_versions(plugin_id, version, digest, manifest_json, status, install_status, active, installed_at, activated_at, rejected_reason, revision, PK(plugin_id, version))`
  - `status` 是 ARCH §6.1 版本生命周期；`install_status` 是独立的安装轴（§6.6），满足“版本状态与安装状态分离”。
  - 部分唯一索引 `plugin_versions_active_idx ... WHERE active = 1`：每插件至多一个已提交版本。
  - `plugin_versions_status_idx(plugin_id, status)` 供恢复扫描。
- `plugin_configs(plugin_id, revision, config_json, active, created_at, applied_at, revision_seq, PK(plugin_id, revision))`
  - `revision` 是对外配置版本 N；`revision_seq` 是该行的 `resource.changed` 序列号（不同编号）。
  - 部分唯一索引保证每插件一个 active；`created_idx`/`revision_idx` 供保留策略。
- `plugin_update_sagas(saga_id, plugin_id, from_version, to_version, mode, strategy, state, step, error, created_at, updated_at, PK(saga_id))`
  - 额外 `mode` 区分 install/update/rollback（rollback 从已安装版本开始，没有 install 步骤）；`strategy` 为 overlap/restart/install。
  - 部分唯一索引 `plugin_update_sagas_running_idx ... WHERE state = 'RUNNING'`：每插件最多一个未完成 saga。
  - 终态 COMMITTED/ROLLED_BACK/FAILED 保留作审计。
- 未增加 `plugin_health`/`plugin_instances`：恢复只需要 saga + 版本行，运行时句柄由 `Runtime` 重新 `Attach`，避免过度设计。
- 所有资源写入都在 `storage.Tx` 内，版本/配置行写 `tx.Changed`（subject：`plugins/<id>/versions/<ver>`、`plugins/<id>/configs/<rev>`）；每步骤和终态写 `tx.AppendEvent`（`plugin.update.step|committed|rolled_back|failed`、`plugin.install.*`、`plugin.config.applied|rejected`）。

## 3. 导出 API

```go
func New(Options) (*Updater, error)
func (u *Updater) Install(ctx, InstallRequest) (*Version, error)
func (u *Updater) Update(ctx, UpdateRequest) (*UpdateResult, error)
func (u *Updater) Rollback(ctx, pluginID string) (*UpdateResult, error)
func (u *Updater) Recover(ctx) ([]string, error)
func (u *Updater) Active(pluginID) (Version, bool)
func (u *Updater) Versions(pluginID) ([]Version, error)
func (u *Updater) ApplyConfig(ctx, ConfigRequest) (ConfigRevision, error)
func (u *Updater) ActiveConfig(pluginID) (ConfigRevision, bool)
func (u *Updater) Routes() *RouteTable
```

- `Runtime`、`MemorySource`、`Installer` 与任务给定签名一致；`Staged` 额外携带 `Handle any`（如 `*install.Staged`）、`ManifestJSON`、`Discard func() error`。
- 请求覆盖：`PackagePath/PluginID`（版本、摘要、manifest 来自 staging）、`Strategy`、`ExpectedRevision`（活动版本/配置的 revision）、`AcceptedCapabilities`、`Timeout`。
- 错误统一 `problem`：非法状态迁移 `STATE_CONFLICT`、revision 不符 `REVISION_CONFLICT`、内存不足 `UNAVAILABLE`、候选失败 `PLUGIN_UNAVAILABLE`、配置字段级 `VALIDATION_FAILED`（保留 `Violations`）、包/安装器内部错误 `INTERNAL`。

## 4. Saga 步骤与 crash 恢复

步骤（`mode` + `strategy` 决定序列）：

| 场景 | 步骤 |
|---|---|
| install | install → start → swap → activate_new → commit |
| update / overlap | install → start → swap → deactivate_old → activate_new → drain_old → release_old → commit |
| update / restart | install → stop_old → start → swap → activate_new → release_old → commit |
| rollback / overlap | arm → start → swap → deactivate_old → activate_new → drain_old → release_old → commit |
| rollback / restart | arm → stop_old → start → swap → activate_new → release_old → commit |

- `step` 列保存“下一步要执行的步骤”；每个步骤先做外部动作（Installer/Runtime），再用一个短事务写版本状态、saga step、`tx.Changed`、审计事件。**事务内从不调用 Runtime**。
- 步骤幂等：`Start` 前先 `Attach` 到已运行进程；`Ready/Activate/Deactivate/Stop/Release` 按 Runtime 契约幂等；`Activate` 成功后再次调用是 no-op，因此恢复不会重复执行后台任务（测试计数 = 1）。
- 顺序与 ARCH §6.3 一致：候选 Start → Ready → 路由快照原子切换 → 旧 Deactivate → 新 Activate → 旧 Stop(drain) → 旧 Release → 提交 ACTIVE。旧版在 COMMITTED 前保持行与文件，可回滚。
- commit 事务先清旧 active，再写新版本 ACTIVE/active=1/activated_at，满足唯一活跃索引；`Active()` 与 `Routes()` 在成功后同时指向新版本。
- `testCrashHook` 是仅测试使用的包级钩子，在每个外部动作之后、记录事务之前触发，用于对每个步骤注入 kill（生产为 nil）。

失败/恢复规则：

- overlap 在 `swap` 之前失败/中断 → 回滚候选（`Deactivate` 如需 → `Stop` → `Release`），旧版 ACTIVE 与路由不变，候选 `ROLLED_BACK`。
- `swap` 及之后失败/中断 → 先 `Deactivate` 候选，路由切回旧版并重新 `Activate` 旧版，再清理候选，saga `ROLLED_BACK`；旧版重新 ACTIVE。
- restart 中途失败 → 恢复旧版（必要时 `Start` + `Ready` + `Activate`），路由切回旧版；旧版重新 ACTIVE。
- install 失败 → `RemoveUnit` + 清理实例，版本 `REJECTED`，saga `FAILED`。
- `Recover` 读取所有 RUNNING saga：overlap 且步骤在 swap 之前 → 回滚；其余 → 从记录步骤继续。步骤错误交给同一 abort 路径。恢复完成写终态并重发路由表；第二次调用无运行 saga、只重发路由，幂等。
- 无法重建计划的 saga（如目标版本行丢失）标记 `FAILED` 并返回错误；崩溃在 install 步骤且 staged 包已不存在时无法续装，按失败回滚，不猜测已发布内容。
- 正常路径旧版 Release 一定发生；crash 后若句柄丢失且 `Attach` 失败（进程已停止），Release 按尽力而为跳过（进程已不在，接口无按 spec 释放的能力），需宿主启动清理兜底。

## 5. 内存 / 配置 / 路由语义

内存 preflight（`MemorySource`，`Options.MemoryReserveBytes` 默认 64 MiB）：

- 任何策略先检查重启预算：`Available + Current >= NewMax + Reserve`，否则 `UNAVAILABLE`（含新 max 本身超预算）。
- `overlap_safe=false`、请求 restart、或 `Available < Current + NewMax + Reserve` → 受控重启；显式请求 overlap 也只会降级，不会升级。
- `Available/Current` 读取失败时保守选择 restart（只打日志，不永久阻塞更新）。
- 安装（无旧版）只检查 `Available >= NewMax + Reserve`。
- `Rollback` 同样做 preflight，故小内存下回滚也走受控重启。

配置：

- `ApplyConfig`：锁定插件 → 校验 `ExpectedRevision`（与当前 active 配置 N 比较，0 表示“尚无配置”）→ 写入非 active 候选快照（`tx.Changed` Created）→ `Runtime.ValidateConfig` → `Runtime.ApplyConfig` → 成功后才在事务内清旧 active、置新 active、写 `applied_at`（`tx.Changed` Updated）。
- 插件拒绝时保留旧 revision，候选行保留为非 active，返回原 `*problem.Error`（保留字段级 `Violations`），并写 `plugin.config.rejected` 审计事件；不会切换指针。
- 保留策略取并集：最近 `Options.KeepConfigs`（默认 20）或 30 天内（`KeepConfigAge`）的配置都保留，active 永不删除；删除旧快照同样发 `tx.Changed` Deleted。
- 若插件成功后宿主事务提交失败，DB 仍指向旧 revision；这是已知窗口，重试 `ApplyConfig` 可收敛（Runtime 侧需幂等）。

路由：

- `RouteTable` 字段私有、构造后不可变；`Lookup/List/Len/Revision` 只读。
- 每次发布都 clone 完整表、递增 revision，再调用 `Runtime.SwapRoutes(next)` 并更新 Updater 的 `atomic.Pointer`。并发读取只会看到旧表或新表；测试用 `-race` 并发读 + 500 次 swap 验证。
- `Recover` 结束时无条件重发一次由 DB active 版本推导的表，保证宿主重启后运行时指针正确。

## 6. 测试与命令

```bash
$env:QWQ_REMOTE_SRC='p3'
& 'C:\Program Files\Git\bin\bash.exe' scripts/remote.sh run 'CGO_ENABLED=1 go test -race -count=1 ./internal/pluginhost/updater/...'
& 'C:\Program Files\Git\bin\bash.exe' scripts/remote.sh run 'go vet ./internal/pluginhost/updater/...'
& 'C:\Program Files\Git\bin\bash.exe' scripts/remote.sh run 'staticcheck ./internal/pluginhost/updater/...'
& 'C:\Program Files\Git\bin\bash.exe' scripts/remote.sh run 'gofmt -l internal/pluginhost/updater'
```

结果：`ok ... 26.512s`；vet/staticcheck 0；gofmt 无输出。测试使用真实 SQLite（`t.TempDir()`）与 fake Runtime/Installer/Memory，覆盖：

- 安装/更新（overlap 顺序、restart）/回滚 happy path；重复版本、expected revision、能力新增拒绝。
- 每个 overlap step 与每个 restart step 注入 kill 后重建 Updater + `Recover`；断言唯一 active、路由一致、无双激活、二次 Recover 幂等。
- install/rollback 中途 crash；swap 后失败回滚；restart 失败恢复旧版；健康检查/Ready/Start/Stop/Release 错误。
- 内存不足降级 restart、连 restart 都不足时 `UNAVAILABLE`。
- 配置校验失败/应用失败保留旧 revision、字段级 violations、保留策略、expected revision。
- 并发读路由 + 多次 swap（race）、同 plugin 并发 Update 串行化、非法状态迁移 `STATE_CONFLICT`。

## 7. 主会话适配说明

`Installer`（`install`/`sandbox` 适配）：

- `Stage`：`install.Extract` 后返回 `Staged{Manifest, ManifestJSON: pkg.ManifestBytes, Digest: 包摘要或留空, Handle: *install.Staged, Discard: func(){st.Delete}}`。摘要留空时用 manifest 字节的 sha256；`PluginID/Version` 可留空由 manifest 填充。
- `InstallUnit`：`Staged.Handle` 调 `Commit(install.VersionDir(root,id,version))`，再用 `sandbox.UnitSpec`（Limits 来自 manifest.Resources）渲染并安装 unit/drop-in。**必须不打扰正在运行的旧版本**（版本目录按版本隔离；unit/drop-in 若按插件命名，需让 ExecStart 指向目标版本且旧实例已由 systemd 保持）。必须可重复调用（恢复会重试）。
- `RemoveUnit`：本包只在“全新安装失败、没有其他 active/运行版本”时调用；适配器可安全删除版本目录与 unit。更新失败不回滚 unit（旧版可能仍在用同名 unit），由宿主后续清理。
- 版本文件保留：本包不删除成功安装的旧版本目录，至少保留当前+上一版；后续版本清理策略留给宿主。
- 同一版本失败后（`ROLLED_BACK`/`REJECTED`）不能再次 `Install`/`Update` 该版本（行已存在），P3 没有卸载 API；宿主需换版本号或手工清理后由后续卸载事务处理。

`Runtime`（`supervisor`/`sandbox` 适配）：

- `Start` 只创建候选、不启动后台工作；对同版本已运行应报错，调用方先 `Attach`。
- `Attach` 用 systemd `MainPID` + `ReattachConfig` 连接，不重启；无实例时返回 error。
- `Ready` 做 transport + 插件自检；`Activate/Deactivate/Stop/Release` 必须幂等，`Stop` 走 drain+`systemctl stop`，禁止 `Client.Kill()`；`Release` 清理 owner（路由/订阅/句柄）。
- `Activate` 必须“成功一次后 no-op”，恢复会重复调用；`Activate` 前不得有任何后台任务。
- `SwapRoutes` 把指针存到实现方的 atomic（请求路径读它，或直接读 `Updater.Routes()`），不能修改传入表。
- `InstanceSpec` 不含版本目录：适配器用自身 plugins root + `install.VersionDir(root, spec.PluginID, spec.Version)` 推导；`Manifest`/`Digest`/`ConfigRevision` 已给足启动信息。
- `ValidateConfig/ApplyConfig` 在事务外调用；`ApplyConfig` 失败必须保证实例仍用旧 revision。
- 非 hot-apply 的受控重启**未在本包实现**：manifest `config.hot_apply=false` 时本包仍调用 `ApplyConfig`，适配器/宿主应拒绝或后续在 Runtime 内实现重启（ARCH §6.5）；这是需要主会话决定的一处。
- 宿主启动流程：`New`（加载 active/配置、不碰运行时）→ `Recover`（解决 RUNNING saga、恢复路由）→ 再对外服务。
