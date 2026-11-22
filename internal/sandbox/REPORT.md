<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# P2-T5 / P2-T8 报告：插件单元模板、privileged helper、doctor 沙箱探测

- 日期：2026-11-01
- 范围：`internal/sandbox/**`（新包）、`cmd/qwq/privileged.go`（新文件）、`internal/doctor/sandbox.go`（新文件）、
  `deployments/systemd/qwq-plugin@.{service,socket}`、`deployments/polkit/qwq-plugin.rules`
- 依据：`spikes/p2t1/REPORT.md` §5/§9、ADR-0003 决策 3/5/7、ARCH 审查 S2、`api/manifest/v1/manifest.schema.json`
- 未改动：`go.mod`/`go.sum`、`api/`、`docs/`、`scripts/`、`cmd/qwq/main.go`（主会话已加 `privileged` case）、其它包的现有文件

## 1. 结论

P2-T5 的可落地形态是「**打包机模板 + 每插件渲染的实例子单元 + 资源 drop-in + 每插件 tmpfiles 片段**」：

- `deployments/systemd/qwq-plugin@.service` 与 `qwq-plugin@.socket` 是宿主编译包里随包安装的**模板**（`%i`/`%t` 形式），
  用于 CI 的 `systemd-analyze verify`、`qwq doctor` 的单元存在性检查和人工审阅。
- `qwq privileged install -spec <json>` 用同一份模板渲染出**具体实例单元**
  `/etc/systemd/system/qwq-plugin@<id>.service` 与 `.socket`（版本固定 `ExecStart`、`ExecStartPre` 摘要校验），
  外加 `qwq-plugin@<id>.service.d/10-resources.conf`、`/etc/tmpfiles.d/qwq-plugin-<id>.conf`、
  `/run/qwq/creds/<id>.token` 与 `/run/qwq/{plugin/<id>,link,creds}`。
- 启动/停止仍由 agent 经 polkit 完成，helper 不参与启停；helper 也不监听任何 socket。
- P2-T8 的探测独立于 `doctor.Run`（`SandboxChecks`），不改变现有 `qwq doctor` 输出；CI 门槛是
  `SandboxScore`（默认 `<= 1.0`，P2-T1 实测 0.6）。

**验证结果**：`internal/sandbox`、`internal/doctor`、`cmd/qwq` 的 `go test` 与 `CGO_ENABLED=1 go test -race` 全通过；
`gofmt -l`、`go vet`、`staticcheck` 全干净；`systemd-analyze verify` 对模板与渲染后的实例子单元只报
「可执行文件不存在」和 systemd 245 的 3 条 pre-247 未知键；渲染出的 tmpfiles 片段被 `systemd-tmpfiles --root=`
接受并生成期望权限；真实非 root 运行 `qwq privileged` 被拒绝。

## 2. 文件

| 文件 | 说明 |
|---|---|
| `internal/sandbox/doc.go` | 包文档：职责边界（不监听、不启停、不接触插件） |
| `internal/sandbox/unit.go` | `UnitSpec`/`Limits`/`Paths`、`RenderUnit`/`RenderResources`/`RenderTmpfiles`、`%i`/`%t` 展开、注入校验 |
| `internal/sandbox/install.go` | `Installer`、`InstallUnit`/`RemoveUnit`、`WriteCredential`、`VerifyEntrypoint`、组管理、原子写 |
| `internal/sandbox/systemctl.go` | `Systemctl` 接口与 `ExecSystemctl`、`UnitStatus`、`systemctl show` 解析、超时 |
| `internal/sandbox/runner.go` | `Runner` 接口与 `ExecRunner`（安装器与 systemctl 共用，测试注入 fake） |
| `internal/sandbox/templates/qwq-plugin@.{service,socket}` | 与 `deployments/systemd/` 逐字节一致的嵌入副本（测试强制） |
| `internal/sandbox/testdata/alpha.{service,socket,resources.conf}` | 黄金文件（`-update` 生成） |
| `internal/sandbox/*_test.go` | 黄金、注入、上限、原子写、组、摘要、systemctl、`systemd-analyze verify` |
| `cmd/qwq/privileged.go` | `runPrivileged`：`render` / `install` / `remove` / `verify-entrypoint`，仅 Linux root，JSON 输出 |
| `internal/doctor/sandbox.go` | `SandboxChecks`、`SandboxScore`、`ParseExposure`、`SandboxOptions` |
| `deployments/systemd/qwq-plugin@.service` | 模板：沙箱 S2 + 资源默认值 + 占位 ExecStart |
| `deployments/systemd/qwq-plugin@.socket` | 模板：systemd 持有监听 socket |
| `deployments/polkit/qwq-plugin.rules` | 只放行 agent 对 `qwq-plugin@<id>.{service,socket}` 的 6 个动词 |

## 3. 单元与渲染

### 3.1 模板为什么不能直接启动

插件的可执行文件路径与摘要只有在包安装、验签之后才知道，而 systemd 单元是静态文件。因此：

- 模板里的 `ExecStartPre=+/opt/qwq/current/bin/qwq privileged verify-entrypoint` 与
  `ExecStart=/opt/qwq/current/libexec/qwq-plugin` 是**占位**；`systemd-analyze verify` 对它们只报
  `Command ... is not executable: No such file or directory`（P2-T5 任务允许）。
- 实例子单元把这两行替换为
  `ExecStartPre=+... verify-entrypoint -dir <versionDir> -entrypoint <entrypoint> -digest sha256:...` 与
  `ExecStart=<versionDir>/<entrypoint>`，不带任何 `%` 说明符残留。
- `ExecStartPre` 用 `+` 前缀：它以 root 身份运行，绕过 `DynamicUser`，只读 0555 的不可变版本目录；
  非 root 的 `qwq privileged` 会直接拒绝（实测 `su nobody` 退出 1）。

### 3.2 关键指令（模板 = 渲染体，只有命令两行与 `%i`/`%t` 不同）

```ini
Requires=qwq-plugin@%i.socket
After=qwq-plugin@%i.socket
Type=exec
DynamicUser=yes
SupplementaryGroups=qwq-p-%i
UMask=0077
LoadCredential=qwq-token:%t/qwq/creds/%i.token
BindPaths=%t/qwq/host/%i:%t/qwq/link
Environment=QWQ_PLUGIN_ID=%i
Environment=QWQ_PLUGIN_SOCKET=%t/qwq/plugin/%i/plugin.sock
Environment=QWQ_HOST_SOCKET=%t/qwq/link/host.sock
KillMode=control-group
KillSignal=SIGTERM
Restart=on-failure / RestartSec=1s / StartLimitIntervalSec=60 / StartLimitBurst=3
```

沙箱（S2 全量，P2-T1 实测可用）：`PrivateNetwork=yes`、`RestrictAddressFamilies=AF_UNIX`、
`NoNewPrivileges=yes`、`ProtectSystem=strict`、`ProtectHome=yes`、`PrivateTmp=yes`、`PrivateDevices=yes`、
`DevicePolicy=closed`、`ProtectKernel{Tunables,Modules,Logs}=yes`、`ProtectControlGroups=yes`、
`ProtectClock=yes`、`ProtectHostname=yes`、`ProtectProc=invisible`、`ProcSubset=pid`、
`RestrictNamespaces=yes`、`RestrictRealtime=yes`、`RestrictSUIDSGID=yes`、`LockPersonality=yes`、
`MemoryDenyWriteExecute=yes`、`SystemCallArchitectures=native`、
`SystemCallFilter=@system-service` + `SystemCallFilter=~@privileged @resources`、
`SystemCallErrorNumber=EPERM`、空 `CapabilityBoundingSet=`/`AmbientCapabilities=`、`KeyringMode=private`。

socket 单元：`ListenStream=%t/qwq/plugin/%i/plugin.sock`、`SocketUser=qwq`（安装器可渲染成 agent 用户）、
`SocketMode=0600`、`Service=qwq-plugin@%i.service`、`RemoveOnStop=yes`、`WantedBy=sockets.target`。

### 3.3 资源默认值与派生

默认值取自 P2-T1 §4/§9（48 MiB、单核、32 任务、256 fd）。drop-in 由 manifest `resources` 覆盖：

| 项 | 单元指令 | 默认 | 边界（manifest schema） |
|---|---|---|---|
| 内存上限 | `MemoryMax=<n>M` | 48M | 16..65536 MB |
| 内存软限 | `MemoryHigh=<0.9n>M` | 43M | 派生 |
| CPU | `CPUQuota=<n>%` | 100% | 1..100000 |
| 任务 | `TasksMax=<n>` | 32 | 1..4096 |
| 文件句柄 | `LimitNOFILE=<n>` | 256 | 16..65536 |
| Go 软限 | `Environment=GOMEMLIMIT=<0.85n>MiB` | 40MiB | 派生 |
| OOM | `OOMScoreAdjust=500` | 固定（不随 manifest） | — |

`MemoryHigh`/`GOMEMLIMIT` 用整数向下取整（32→28/27，48→43/40，65536→58982/55705，测试固定）。
`CPUQuota=100%` 是**字面百分号**，渲染器只拒绝 `%[A-Za-z%]` 形式的残留说明符，不会误伤它。

### 3.4 运行时目录与 tmpfiles（P2-T1 遗留项）

`/run` 是 tmpfs，`.socket` 单元无法创建自己要监听的目录，`RuntimeDirectory=` 又会把共享的 `/run/qwq`
一起 chmod/chown。因此 helper 在安装时创建目录并写**每插件 tmpfiles 片段**：

```
d /run/qwq/plugin 0711 root root -
d /run/qwq/plugin/<id> 0711 root root -
d /run/qwq/link 0711 root root -
d /run/qwq/creds 0700 root root -
```

- `/run/qwq` 本身仍由 `deployments/tmpfiles/qwq.conf`（0750 qwq:qwq）负责；按文件名排序
  `qwq-plugin-<id>.conf` 先于 `qwq.conf`，若片段先跑会在同一轮 tmpfiles 内把 `/run/qwq` 建成 root 0755，
  随后被宿主条目改回 qwq:qwq 0750——同一轮内完成，sockets.target 在其后。已在构建机用
  `systemd-tmpfiles --root=` 验证片段语法与最终权限（`creds` 0700、`link`/`plugin` 0711）。
- `plugin.sock` 目录 root 0711：插件（DynamicUser）无需访问它（fd 继承），其他插件无法列举/连接。
- 宿主通道目录 `/run/qwq/host/<id>` 仍由 agent 运行时创建（2750，属组 `qwq-p-<id>`）；`/run/qwq/link`
  只作为 bind mount 目标由 helper 预建。

## 4. 导出 API（`internal/sandbox`）

```go
func ValidateID(id string) error                    // manifest id 文法 + MaxIDLen(26)
func UnitNames(id string) (service, socket string, err error)
func GroupName(id string) (string, error)          // qwq-p-<id>
func TmpfilesName(id string) (string, error)       // qwq-plugin-<id>.conf
func PathsFor(runtimeBase, id string) (Paths, error)

type Limits struct{ MemoryMaxMB, CPUQuotaPercent, PIDsMax, FDsMax int64 }
func DefaultLimits() Limits
func (Limits) Validate() error
func (Limits) MemoryHighMB() int64
func (Limits) GOMEMLIMITMiB() int64
func RenderResources(Limits) ([]byte, error)

type UnitSpec struct {
    ID, VersionDir, Entrypoint, Digest, Executable, RuntimeBase, AgentUser string
    Limits *Limits
}
func RenderUnit(UnitSpec) (map[string][]byte, error)   // service + socket + drop-in
func RenderTmpfiles(UnitSpec) ([]byte, error)

type Runner interface{ Run(ctx, name, args...) (string, error) }
type ExecRunner struct{}
type Installer struct{ UnitDir, TmpfilesDir, RuntimeBase, AgentUser string; Runner Runner }
func DefaultInstaller(Runner) Installer
func (Installer) Install(ctx, UnitSpec, credential []byte) (InstallResult, error)
func (Installer) Remove(ctx, id string) (RemoveResult, error)
func InstallUnit(ctx, UnitSpec, destDir string) ([]string, error)
func RemoveUnit(id, destDir string) ([]string, error)
func WriteFileAtomic(path string, data []byte, mode fs.FileMode) error
func WriteCredential(dir, id string, token []byte) (string, error)
func VerifyEntrypoint(versionDir, entrypoint, digest string) error   // 复用 pkgfile.VerifyFile
func CreatePluginGroup(ctx, Runner, name string) error               // groupadd --system --force
func RemovePluginGroup(ctx, Runner, name string) error               // groupdel（不存在视为成功）

type UnitStatus struct{ MainPID int; ControlGroup, ActiveState, SubState, FragmentPath string; StartTime time.Time }
type Systemctl interface{ Start/Stop/Kill(ctx, unit) error; Show(ctx, unit) (UnitStatus, error) }
func CheckUnitName(unit string) error
type ExecSystemctl struct{ Runner Runner; Timeout time.Duration }
func NewExecSystemctl(Runner) *ExecSystemctl
```

关键行为：

- 拒绝而非转义：id 文法/长度、绝对干净路径、`bin/<name>` 入口、`sha256:<64hex>` 摘要、`RuntimeBase`/`AgentUser`，
  以及任何控制字符、空白、`%`、引号、反斜杠（换行注入测试逐项覆盖）。`Executable` 必须等于
  `VersionDir/Entrypoint`，防止渲染未被验签的路径。
- 文件 0644 root、目录 0711/0700、credential 0600；全部先写临时文件 → `chmod` → `fsync` → `rename` → `fsync(dir)`。
- `RemoveUnit` 同时删除 `qwq-plugin@<id>.service.d/`（该目录只放 helper 渲染的 drop-in）；缺失文件不算错误，
  可重复执行。
- `Systemctl.Show` 每次调用 `systemctl show -p MainPID -p ControlGroup -p ActiveState -p SubState
  -p FragmentPath -p ExecMainStartTimestamp <unit>`，**从不缓存**；`Kill` 用
  `kill --kill-whom=main -s SIGKILL`；单元名白名单（排除以 `-` 开头的参数注入）。

## 5. helper CLI（`qwq privileged`）

```
qwq privileged render            -spec <json> -out <dir>
qwq privileged install           -spec <json> [-credential-stdin]
                                 [-unit-dir] [-tmpfiles-dir] [-runtime-base] [-agent-user]
qwq privileged remove            -id <id> [同上路径参数]
qwq privileged verify-entrypoint -dir <versionDir> -entrypoint <rel> -digest sha256:...
```

- 仅 `linux` + `Geteuid()==0`，否则 `{ok:false,error:"...must run as root"}` 且退出 1；不接受相对 `-spec`；
  spec ≤64 KiB、`DisallowUnknownFields`、拒绝尾部多余数据；token 只从 stdin 读（≤4 KiB，去掉一个换行），
  绝不出现在 argv/journal。
- 每个命令输出**一个 JSON 对象**到 stdout（`ok/command/id/group/files/dirs/tmpfiles/credential/error`），
  人类可读一行到 stderr；退出码 0/1/2。
- `render` 只写 `<out>/systemd/**` 与 `<out>/tmpfiles.d/<name>`，是安装前审阅/CI 的干跑。

## 6. doctor（P2-T8）

`SandboxChecks(env, SandboxOptions)` 返回 9 条，ID 均带 `sandbox-` 前缀，避免与 `doctor.Run` 的 ID 混淆：

| ID | 探测 | 判定 |
|---|---|---|
| `sandbox-systemd` | `systemctl --version` | ≥249 OK；247–248 Warn；<247 Fail |
| `sandbox-cgroup` | `/sys/fs/cgroup/cgroup.controllers` | 缺失 Fail（v1/hybrid）；缺控制器 Warn |
| `sandbox-userns` | `/proc/sys/kernel/unprivileged_userns_clone`（存在时） | 1 OK；0 Info（模板不用 PrivateUsers）；缺失 Info |
| `sandbox-seccomp` | `/proc/self/status` 的 `Seccomp` + `actions_avail` | 无字段 Fail；缺 `errno` Warn |
| `sandbox-virt` | `systemd-detect-virt`（复用 `checkVirt`） | 容器 Warn |
| `sandbox-exposure` | `systemd-analyze security <unit>` 解析 `Overall exposure level ...: 0.6` | > 阈值 Warn；单元未安装 Info |
| `sandbox-polkit` | `systemctl show -p ActiveState/LoadState/UnitFileState polkit.service` | active OK；loaded 但 inactive Info（D-Bus 激活）；未安装 Warn |
| `sandbox-runtime` | `Stat(/run/qwq)` | 缺失 Warn + tmpfiles Fix |
| `sandbox-units` | `Stat(<unitDir>/qwq-plugin@.{service,socket})` | 缺失 Warn + 安装/daemon-reload Fix |

```go
const DefaultMaxExposure = 1.0
type SandboxOptions struct{ UnitDir, RuntimeDir, Unit string; MaxExposure float64 }
func SandboxChecks(env Env, opts SandboxOptions) []Result
func SandboxScore(env Env, opts SandboxOptions, limit float64) (score float64, ok bool, err error) // limit<=0 → 默认
func ParseExposure(out string) (float64, error)   // 兼容 245/255 两种措辞，拒绝 0..10 之外
```

门槛用法（供 CI/安装器）：`Worst(SandboxChecks(...)) != Fail` 且 `SandboxScore(..., 0)` 返回 `ok`；
`systemd-analyze` 缺失或单元未安装时 `SandboxScore` 返回 error，不会把「测不到」当成 0 分。

## 7. 测试与验证（构建机 Ubuntu 20.04 / systemd 245 / Go 1.27.3）

```text
$ go vet ./internal/sandbox/ ./internal/doctor/ ./cmd/qwq/          # OK
$ staticcheck ./internal/sandbox/ ./internal/doctor/ ./cmd/qwq/    # OK
$ gofmt -l internal/sandbox internal/doctor cmd/qwq                # 空
$ go test -count=1 ./internal/sandbox/ ./internal/doctor/ ./cmd/qwq/   # ok / ok / ok
$ CGO_ENABLED=1 go test -race -count=1 同上                            # ok / ok / ok
$ go build ./...                                                    # OK
```

覆盖（节选）：黄金文件（单元 + drop-in）；模板与 `deployments/systemd/` 逐字节一致；S2 指令清单固定；
`%i`/`%t` 展开与占位行替换；注入与越界拒绝（id/路径/入口/摘要/用户/limits/换行/`%`/引号）；`PathsFor`；
`Limits` 派生与边界；原子写（父目录、覆盖、无临时文件残留、拒绝相对/脏路径/零模式）；`InstallUnit`/`RemoveUnit`
（可重复、缺文件容忍、取消的 ctx）；`WriteCredential`（0600、目录 0700、短/超长/换行/空格/NUL、符号链接目录）；
`VerifyEntrypoint`（正确摘要、篡改、缺失、非普通文件、符号链接版本目录）；组管理 fake Runner（参数、已存在、
仍在用）；`Installer.Install/Remove`（组、目录权限、tmpfiles 内容、credential 内容/权限、结果 JSON、二次 Install/Remove、
缺 runtime 目录、坏 token/id 在写盘前拒绝）；`Systemctl`（命令参数、show 解析、`MainPID=0`、缺属性/坏值/命令失败、
单元名白名单、超时与 ctx 取消、`ExecMainStartTimestamp` 解析）；doctor（目标机全绿、缺 systemd、cgroup v1/缺控制器、
polkit active/inactive/未装/查不到、userns 0/缺失、seccomp 无字段/无 errno、runtime/units 缺失、分数超限、
自定义 unit/阈值、`ParseExposure` 4 正 4 负、`SandboxScore` 门槛与错误路径）。

`systemd-analyze verify`（测试内置，构建机实测）：

```text
qwq-plugin@.service: 3 条 pre-247 未知键（LoadCredential/ProtectProc/ProcSubset）
                     + 2 条占位可执行文件不存在
qwq-plugin@.socket:  同 3 条未知键，退出码 0
渲染后的 qwq-plugin@alpha.service: 同 3 条未知键 + 2 条不存在
                    （/opt/qwq/current/bin/qwq、/var/lib/qwq/plugins/alpha/1.2.3/bin/plugin）
```

测试把这 4 类之外的一切诊断视为失败（`TestSystemdAnalyzeVerify`，渲染单元也包含在内）。

端到端人工验证（构建机，`go build -o /tmp/qwq-e2e ./cmd/qwq`）：

```text
$ /tmp/qwq-e2e privileged render -spec /tmp/spec.json -out /tmp/render   # ok，4 个文件 0644
$ systemd-tmpfiles --root=/tmp/tfroot2 --create qwq-plugin-alpha.conf    # rc=0
  drwx------ creds / drwx--x--x link / drwx--x--x plugin / plugin/alpha
$ /tmp/qwq-e2e privileged verify-entrypoint -dir /tmp/ver ...           # ok
$ 同上，摘要改 0                                                         # rc=1 PKG_DIGEST_MISMATCH
$ su -s /bin/sh nobody -c '/tmp/qwq-e2e privileged verify-entrypoint ...'  # rc=1 "must run as root"
```

polkit 规则：用 python 提取文件中的正则并核对 9 个单元名——`security.scan`/`a-b.c` 通过，
`Alpha`/无后缀/其他前缀/`;x`/`.exe` 全部不匹配；构建机没有 JS 引擎，未做 `node --check` 级语法验证。

## 8. 未完成 / 风险

1. **没有在带 systemd 的目标机上真实插拔单元**：本任务的构建机是 systemd 245 / cgroup hybrid，且规则只允许
   在构建机上跑单测与 verify。`systemd-analyze security` 需要单元被 systemd 加载（245 不支持离线文件分析），
   所以分数门槛只在单测里用 P2-T1 的实测输出验证；真机由测试机（systemd 255）做一次
   `systemd-analyze security qwq-plugin@alpha.service` 更稳妥，预期 ≤1.0。
2. **`LoadCredential`/`ProtectProc`/`ProcSubset` 在 systemd <247 上会被忽略**：verify 的 3 条未知键就是它。
   `doctor` 已把 <247 判为 Fail（第三方插件拒绝安装），但模板本身仍可被 245 加载——安装器必须遵守 doctor 结论。
3. **启用/开机自启未纳入 helper**：polkit 规则故意不给 agent `manage-unit-files`，`.socket` 的
   `enable`（`sockets.target` 的 wants 链接）需要安装脚本以 root 完成，或后续由 helper 增加一个
   `enable -id` 子命令。当前 helper 只写文件，不 enable/start/daemon-reload——调用方必须自己
   `systemctl daemon-reload`（P2-T7 agent 或安装脚本）。
4. **`ExecStartPre` 以 root 运行**（`+`）：这是让 `qwq privileged` 保持 root-only 的同时在启动前做摘要校验的
   代价；它只读 0555 的版本目录，但确实在沙箱外执行。若后续改成插件 uid 可执行的独立校验器，可以去掉 `+`。
5. **polkit 只能按单元名模式放行**（P2-T1 §5 的局限），不能白名单「已安装的 id」；规则文件是静态的，
   任何符合 `qwq-plugin@[a-z][a-z0-9]*([.-][a-z0-9]+)*` 的单元都能被 agent 启停。若要收紧，需 helper 生成
   实例白名单或改用 helper IPC（未做）。
6. **`StartTime` 解析依赖本地时区**：`ExecMainStartTimestamp` 是 `Mon 2006-01-02 15:04:05 ZONE` 的本地时间，
   解析时丢弃时区缩写、按 `time.Local` 解释；无法解析时返回零值（supervisor 会退化为只用 MainPID 识别
   generation，PID 复用窗口变大）。彻底消除需要读 `/proc/<pid>/stat` 第 22 字段并折进时间戳（supervisor REPORT 已提到）。
7. **id 长度上限 26**：manifest 允许 128，但 `qwq-p-<id>` 要满足 shadow 工具 32 字符上限。超长 id 会被
   `sandbox.ValidateID` 明确拒绝，不会产生半安装状态。
8. **`LimitNOFILE=256` 默认值**来自 spike 的运行值；manifest 的 `fds_max` 会覆盖它，但没有在真实插件上压测 fd 打满。
9. **`remove` 不停止运行中的单元**：删掉单元文件不会停进程，调用方必须先 `systemctl stop`（agent 的职责）。
10. **agent 用户名的三处一致**：polkit 规则的 `subject.user`、helper 的 `-agent-user`/`SocketUser=`、
    以及 agent 单元（尚未编写）的 `User=` 必须是同一个名字。默认取 `qwq`（与现有
    `deployments/tmpfiles/qwq.conf`、`qwq-controller.service` 一致）；ADR-0003 §5 把该用户写作 `qwq-agent`，
    若主会话按 ADR 建独立用户，需要同时改 polkit 规则并重新安装所有插件（socket 属主随之变化）。
11. **`deployments/README.md` 仍写着「插件单元是 P2-T5/T7 工作」**，未在本次范围内更新；建议主会话补
    `/run/qwq/plugin`、`/etc/tmpfiles.d`、`/etc/polkit-1/rules.d` 三项磁盘契约，并把 `/run/qwq` 的属主与新
    agent 用户对齐（当前 tmpfiles 是 `qwq:qwq 0750`，独立 agent 用户将无法穿越）。
12. **`internal/pluginhost/supervisor` 的 `UnitManager` 适配**：它的 `Show` 需要 `ExecMainStartTimestamp`，
    `internal/sandbox.ExecSystemctl.Show` 已提供 `UnitStatus.StartTime`；适配层只需
    `UnitNames(pluginID)` + 三个方法转发，尚未接线（`cmd/qwq/serve-agent.go` 里仍是 `unwiredUnits`）。
13. **egress 代理**（IMPLEMENTATION-PLAN P2-T5 列出的「默认拒绝回环/链路本地/私网」）不在本任务清单内，
    本次只落了 `PrivateNetwork=yes` + `RestrictAddressFamilies=AF_UNIX` 的默认无网络基线。

## 9. 复现命令

```sh
source scripts/dev-env.sh
gofmt -l internal/sandbox internal/doctor cmd/qwq
go vet ./internal/sandbox/ ./internal/doctor/ ./cmd/qwq/
staticcheck ./internal/sandbox/ ./internal/doctor/ ./cmd/qwq/
go test -count=1 ./internal/sandbox/ ./internal/doctor/ ./cmd/qwq/
CGO_ENABLED=1 go test -race -count=1 ./internal/sandbox/ ./internal/doctor/ ./cmd/qwq/
go test -run TestRenderUnitGolden -update ./internal/sandbox/    # 只在有意改单元时执行
systemd-analyze verify deployments/systemd/qwq-plugin@.service   # 只接受"缺可执行文件"与 pre-247 未知键
```
