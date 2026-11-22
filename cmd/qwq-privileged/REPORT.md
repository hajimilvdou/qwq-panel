<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# P3 报告：root 特权助手 `qwq-privileged`（socket 激活、空闲 0）

- 日期：2026-11-02
- 范围：`cmd/qwq-privileged/**`（新）、`internal/sandbox/helper.go`（新）、
  `internal/sandbox/helper_test.go`（新）、`internal/sandbox/install.go`（`InstallResult.Warnings`）、
  `internal/sandbox/doc.go`、`internal/controller/updater_runtime.go`（+ 新测试）、
  `cmd/qwq/serve.go`、`deployments/systemd/qwq-privileged.{socket,service}`（新）、
  `deployments/tmpfiles/qwq.conf`、`deployments/README.md`
- 未改：`go.mod`/`go.sum`、`api/`、`sdk/`、其它 `internal/*` 语义、`服务器/`、`scripts/remote*.env`

## 1. 结论

`serve-controller` 继续以普通用户 `qwq` 运行；写 `/etc/systemd/system`、`/etc/tmpfiles.d`、`/run/qwq`，
发布/删除 `/var/lib/qwq/plugins/<id>/<version>` 的动作移到一个独立 root 程序 `qwq-privileged`。
它由 systemd socket 激活：socket 单元常驻，收到连接才启动服务，**每个激活只处理一个请求就退出**，
因此空闲时没有 root 进程（`systemctl is-active qwq-privileged.service` = `inactive`，socket 仍
`active`）。没有把 `qwq` setuid，也没有让 controller 以 root 运行。

`PluginInstaller` 增加可选的 `Helper *sandbox.HelperClient`：非 nil 时 `InstallUnit` 先让 helper
`publish` 已验签的 staging 树，再传 `UnitSpec` + 新生成的 token 调 `install`；`RemoveUnit` 也交给
helper。`nil` 时保留原 in-process `Commit` 行为（root 主机、测试）。
`serve-controller --privileged-socket` 默认 `/run/qwq/privileged.sock`，socket 存在才构造 helper，
否则告警并回退。

staging 根从 `<plugins>/.staging` 改为 qwq 可写的 `/var/lib/qwq/staging`（`DefaultStagingRoot`），
因为 `/var/lib/qwq/plugins` 属于 root:root 0755；helper 只读 staging，publish 完成后 controller 自己
`Discard` staging。

## 2. 文件

| 文件 | 说明 |
|---|---|
| `cmd/qwq-privileged/main.go` | 入口、flag、root/Linux 检查、`LISTEN_FDS` 接管 fd 3、手动 `--socket` 调试监听、信号退出 |
| `cmd/qwq-privileged/server.go` | 请求分发、publish/install/remove/reload/ping、staging 树校验与复制、路径/用户/命令白名单、systemd 调用、panic 恢复 |
| `cmd/qwq-privileged/main_test.go` | `LISTEN_FDS`/`LISTEN_PID` 解析、非 root 拒绝、坏参数/相对 socket |
| `cmd/qwq-privileged/server_test.go` | 协议、install/remove/reload/ping、恶意 spec、运行中拒绝、enable 告警、panic、Unix socket 端到端、并发上限 4、publish 成功/幂等/坏路径/符号链接父目录 |
| `cmd/qwq-privileged/server_linux_test.go` | Linux 专属：staging 树中的符号链接、FIFO、控制字符文件名被拒绝 |
| `internal/sandbox/helper.go` | 线上协议类型（含 publish）、`HelperClient`、连接重试、`Read/WriteHelperJSON`、problem 映射 |
| `internal/sandbox/helper_test.go` | fake Unix server：install/publish/remove/ping、拒绝码/超时/仅连接重试/坏响应/1 MiB 上限 |
| `internal/sandbox/install.go` | `InstallResult/RemoveResult.Warnings`（helper 非致命告警经 client 回传） |
| `internal/controller/updater_runtime.go` | `DefaultStagingRoot`、`PluginInstaller.Helper`、`publishVersion`、token 生成、`installUnit`、`RemoveUnit` 分支、错误码保留 |
| `internal/controller/updater_runtime_helper_test.go` | fake helper 端到端：publish/install 请求字段、token、staging 清理、`keep_unit`、错误码、Helper=nil 的 credential 文件 |
| `cmd/qwq/serve.go` | `--privileged-socket`、`--staging-dir`（默认 `DefaultStagingRoot`）、socket 存在检测、helper 构造与日志 |
| `cmd/qwq/serve_privileged_test.go` | `newPrivilegedHelper` 三态（缺失/普通文件/socket）、相对 socket/staging 用法错误 |
| `deployments/systemd/qwq-privileged.socket` | `ListenStream=/run/qwq/privileged.sock`、`SocketMode=0660`、`SocketGroup=qwq`、`RemoveOnStop=yes` |
| `deployments/systemd/qwq-privileged.service` | root、`ExecStart=/usr/local/bin/qwq-privileged`、无网络、只读根 + 3 个可写路径、staging 只读、最小 capability、`MemoryMax=32M`、`TasksMax=16` |
| `deployments/tmpfiles/qwq.conf` | 说明 `/run/qwq` 必须先存在；新增 `/var/lib/qwq/staging`（qwq:qwq 0700，publish 的只读源） |

## 3. 协议

一个连接 = 一个请求 + 一个响应；每边一个 JSON 对象、`\n` 结尾、上限 1 MiB；未知字段直接拒绝。
帮助进程不 multiplex：客户端每次调用新连接，服务端每连接只读一个对象。

```json
// 请求（publish）
{"op":"publish","staged_dir":"/var/lib/qwq/staging/.staging-abc",
 "version_dir":"/var/lib/qwq/plugins/alpha/1.2.3","plugin_id":"alpha","version":"1.2.3"}
// 响应
{"ok":true,"publish":{"id":"alpha","version":"1.2.3","version_dir":"...","files":12,"dirs":4}}
// 请求（install）
{"op":"install","spec":{"id":"alpha","version_dir":"/var/lib/qwq/plugins/alpha/1.2.3",
  "entrypoint":"bin/plugin","digest":"sha256:...","limits":{"memory_max_mb":32,...}},
 "credential_base64":"..."}
// 响应
{"ok":true,"install":{"id":"alpha","group":"qwq-p-alpha","unit_files":[...],"dirs":[...],
  "tmpfiles":"/etc/tmpfiles.d/qwq-plugin-alpha.conf","credential":"/run/qwq/creds/alpha.token"},
 "warnings":["..."]}
// 失败
{"ok":false,"code":"PRECONDITION_FAILED","error":"Plugin alpha is still running ..."}
```

| op | 字段 | 行为 |
|---|---|---|
| `publish` | `staged_dir`, `version_dir`, `plugin_id`, `version` | 校验 staging 树（无符号链接/设备/FIFO/控制字符名）后复制到 plugin 父目录下的临时树，目录 0555、文件 0444（保留可执行位）、root 所有、逐文件 fsync + 父目录 fsync，再 rename 到版本目录；已存在的版本目录只有内容摘要一致才幂等成功 |
| `install` | `spec`, `credential_base64` | 写 unit/socket/drop-in/tmpfiles/credential（0600）、建组、`systemctl daemon-reload`、若 socket 单元存在则 `systemctl enable --now qwq-plugin@<id>.socket`；enable 失败只进 `warnings` |
| `remove` | `id`, `version`, `paths`, `keep_unit` | 先 `systemctl show -p MainPID` 拒绝运行中；`systemctl disable --now qwq-plugin@<id>.socket`（仅 warning）；`sandbox.Installer.Remove`（`keep_unit` 时跳过）；删除版本目录与空的 `<plugins>/<id>`；`daemon-reload`；幂等 |
| `reload` | — | 只 `systemctl daemon-reload` |
| `ping` | — | `{"ok":true,"version":"0.1.0","uid":0}` |

`HelperClient{Socket, Timeout}` 提供 `Publish/Install/Remove/Reload/Ping`，全部返回/包装
`*problem.Error`；只有**连接失败**重试（默认 3 次、50 ms），已发出的请求绝不重试（避免重复发布/
安装/删除）。默认超时 30 s。

## 4. 安全校验

- **仅 root/Linux**：`geteuid() != 0` 或非 Linux 直接退出码 1（`geteuid` 可注入，测试覆盖）。
- **仅 Unix socket**：systemd 模式只接管 fd 3 并要求是 `*net.UnixListener`；`LISTEN_FDS` 必须为 1，
  `LISTEN_PID` 必须等于本进程，否则拒绝而不是回退去抢同一路径。手动模式删除旧 inode 前确认它是
  socket（绝不覆盖普通文件），chmod `0660` + chown `root:<socket-group>`。关闭 `SetUnlinkOnClose(false)`，
  退出时不会删掉 systemd 的 socket 路径。无 TCP、`PrivateNetwork=yes`、`RestrictAddressFamilies=AF_UNIX`。
- **请求体**：严格 JSON、拒绝未知字段、1 MiB 上限、30 s deadline、并发上限 4；
  解码失败只回通用错误，**日志不记录请求体/ token**。
- **路径白名单**：`version_dir` 必须严格等于 `<plugins-root>/<id>/<version>`（绝对、clean、无 `..`、
  真实目录且非符号链接）；`staged_dir` 必须是 `<staging-root>/.staging-*` 的直接子目录（真实目录、非
  符号链接）；unit/tmpfiles/runtime 路径由 helper 自己的 flag 决定，请求不能改；remove 的 `paths` 只
  接受同一个精确版本目录。相对路径、穿越、转义逐项测试。
- **publish 树校验**：复制前 `WalkDir` 拒绝符号链接、设备、FIFO、socket，拒绝空/`.`/`..` 分量、
  超过 255 字节的分量、控制字符文件名；读取通过 `os.OpenRoot` 限制在 staging 根内；写入在
  `<plugins>/<id>` 下新建临时树，组件来自已校验的 WalkDir 相对路径，最后 rename；`<plugins>/<id>` 若
  是符号链接或普通文件则拒绝（防止写穿）。staging 根与 plugins 根不允许重叠（启动配置校验）。
- **agent_user**：只接受 helper 配置的 `qwq`（空则填默认），其它用户名拒绝。
- **spec 校验**：`sandbox.ValidateID` + 纯函数 `sandbox.RenderUnit` 复核 entrypoint、digest、executable、
  limits 与所有进入 unit 的字符串（注入、specifier、控制字符）。
- **无任意命令**：helper 只调用 `systemctl` 四个白名单形式（`daemon-reload`、
  `show -p MainPID qwq-plugin@<id>.service`、`enable --now qwq-plugin@<id>.socket`、
  `disable --now qwq-plugin@<id>.socket`）和
  `groupadd --system --force qwq-p-<id>` / `groupdel qwq-p-<id>` / `getent group qwq-p-<id>`；
  其余一律拒绝。
- **panic** 被 `recover` 成 `{"ok":false,"code":"INTERNAL"}`，不会裸崩。

## 5. systemd 单元

- `qwq-privileged.socket`：`ListenStream=/run/qwq/privileged.sock`、`SocketMode=0660`、
  `SocketGroup=qwq`、`RemoveOnStop=yes`、`Service=qwq-privileged.service`、`WantedBy=sockets.target`。
- `qwq-privileged.service`：`Type=exec`、`Restart=no`、`ExecStart=/usr/local/bin/qwq-privileged --socket
  /run/qwq/privileged.sock`、`UMask=0022`、`MemoryMax=32M`、`TasksMax=16`（`GOMAXPROCS=2` 压住线程数）、
  `PrivateNetwork=yes`、`RestrictAddressFamilies=AF_UNIX`、`ProtectSystem=strict`、
  `ReadWritePaths=/etc /run/qwq /var/lib/qwq/plugins`、`ReadOnlyPaths=-/var/lib/qwq/staging`、
  `CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE`、`NoNewPrivileges=yes`、
  `SystemCallFilter=@system-service`。
  注意 `ReadWritePaths` 必须包含整个 `/etc`（而非只列 `/etc/systemd/system`）：`groupadd/groupdel`
  通过锁文件 + 原子替换改写 `/etc/group`、`/etc/gshadow`，只放开单个文件不够；`ProtectSystem=strict`
  对 `/usr`、`/boot`、`/efi` 仍然生效。`ReadOnlyPaths` 只是把 publish 的源目录显式标为只读，`-` 前缀
  允许该目录尚未创建时服务仍可启动。这一点列入 §8 第 8 项的加固核对。
  另外 seccomp 的 `~@privileged` 会连同 `@chown`（`fchown`）一起拒绝，而 shadow 写备份文件
  `/etc/group-`、`/etc/gshadow-` 时需要 `fchown` 保持属主/属组；因此 deny 列表必须显式展开为
  `@privileged` 去掉 `@chown`（`@resources` 保持拒绝），否则首次 `groupadd` 和卸载时的 `groupdel`
  都会报 `failure while writing changes to /etc/group`。证据与探针见 `REPORT-GROUP.md`。
- `/run/qwq` 由 `deployments/tmpfiles/qwq.conf` 创建为 `qwq:qwq 0750`；socket 文件由 socket 单元建为
  `root:qwq 0660`。controller（qwq）可连，插件（DynamicUser）不可连。
- `RemoveOnStop=yes` 只作用于 socket 单元自身停止；helper 每次激活退出不会删除监听路径。
- 构建机 systemd（245，pre-247）对 `ProtectProc=`/`ProcSubset=` 报 unknown key 并忽略，与既有
  `qwq-plugin@.service` 模板一致；`systemd-analyze verify` 另外只报 `ExecStart` 路径不存在（预期）。

## 6. 接线

- `PluginInstaller.publishVersion`：`Helper != nil` 时调 `Helper.Publish(stagedDir=src.Dir(),
  versionDir, pluginID, version)`，成功后 `DiscardStaged()` 清理 staging；失败用
  `wrapInstallerFailure` 保留 helper 的 problem code（如 `UNAVAILABLE`/`PRECONDITION_FAILED`）。
  版本目录已存在时：若 staging 还在，让 helper 做内容摘要比较；staging 已被清理的重试则信任不可变
  目录（与旧 in-process 行为一致）。`Helper == nil` 时保留原 `src.Commit` + `Discard`。
- `PluginInstaller.InstallUnit`：在 publish 之后生成 32 字节随机 token
  （`base64.RawURLEncoding`，43 个字符，落在 `sandbox.MinTokenLen..MaxTokenLen` 内），然后
  `installUnit(ctx, spec, token)`。token 只进入 helper 请求的 `credential_base64` 和最终 0600
  credential 文件，不写日志、事件、数据库或响应（响应只有 credential 路径）。
- `PluginInstaller.installUnit`：`Helper != nil` → `Helper.Install(ctx, spec, credential)`，否则
  `Sandbox.Install(ctx, spec, credential)`。安装告警写 `WarnContext`；失败用
  `wrapInstallerFailure` 包装，保留 helper 的 problem code，纯 in-process 错误仍是 `INTERNAL`。
- `PluginInstaller.RemoveUnit`：`Helper != nil` → `Helper.Remove`，`Paths=[versionDir]`，
  `KeepUnit = len(otherVersions)>0`；helper 先 `disable --now` 掉该插件 socket（失败仅告警），
  再删除 root 拥有的 unit/凭据/组与版本树（controller 作为 qwq 删不动），最后 `daemon-reload`。
  `Helper == nil` 时原逻辑不变。
- `serve.go`：`--privileged-socket`（默认 `sandbox.DefaultPrivilegedSocket`，空字符串禁用，必须绝对路径）；
  `--staging-dir`（默认 `controller.DefaultStagingRoot`，必须绝对路径并位于 controller 可写的文件系统）；
  `newPrivilegedHelper` 仅当 `os.Stat(socket)` 是 socket 时构造 client，否则告警并回退 in-process。
  `newUpdater` 日志带 `privileged_helper=true/false` 和 `staging_dir`。
- helper 的 `--plugins-root` / `--staging-root` 默认分别为 `/var/lib/qwq/plugins` 与
  `/var/lib/qwq/staging`，必须与 controller 的 `--plugins-dir`、`--staging-dir` 一致；两个根在
  helper 启动时校验不得重叠。
- 原 `qwq privileged` 子命令保留：`verify-entrypoint` 仍是 unit 的 `ExecStartPre`；`install/remove` 供
  root 手工操作/紧急恢复，不再是生产安装路径。

## 7. 测试

构建机（`QWQ_REMOTE_SRC=priv1`，Linux/amd64，Go 1.27.3）：

```sh
CGO_ENABLED=1 go test -race -count=1 \
  ./cmd/qwq-privileged/... ./internal/sandbox/... ./internal/controller/... ./cmd/qwq/...
go vet ./cmd/qwq-privileged/... ./internal/sandbox/... ./internal/controller/... ./cmd/qwq/...
gofmt -l cmd/qwq-privileged internal/sandbox internal/controller cmd/qwq
staticcheck ./cmd/qwq-privileged/... ./internal/sandbox/... ./internal/controller/... ./cmd/qwq/...
```

结果见 §7.1。

### 7.1 结果

本轮最终全量（含新增 publish/token 用例）：

- `CGO_ENABLED=1 go test -race -count=1 ./cmd/qwq-privileged/... ./internal/sandbox/... ./internal/controller/... ./cmd/qwq/...`：
  **四个包全部 `ok`**。新增覆盖：publish 成功、幂等、内容不一致拒绝、恶意 staging/version 路径、
  staging 树符号链接/FIFO/控制字符文件名、符号链接 plugin 父目录、plugins root 缺失；Helper=nil 与
  Helper!=nil 两条 InstallUnit 的 token 生成、0600 credential、staging 清理、日志/响应不含 token。
- `gofmt -l cmd/qwq-privileged internal/sandbox internal/controller cmd/qwq`：无输出。
- `go vet`、`staticcheck` 对上述四个包：无告警。
- `python3 tools/repo_lint.py`：`spdx/boundary/secrets/versions` 全 ok。
- `go build -o /tmp/qwq-privileged-test ./cmd/qwq-privileged`：成功。
- `systemd-analyze verify deployments/systemd/qwq-privileged.{socket,service}`：socket 无输出；service 在
  systemd 245 上只报 `ProtectProc`/`ProcSubset` unknown key（与既有插件模板一致，pre-247 忽略）和
  `ExecStart=/usr/local/bin/qwq-privileged` 不存在（未安装，预期）；`ReadOnlyPaths=-...` 未产生告警。
- `systemctl show -p MainPID qwq-plugin@definitely-missing.service` 在构建机返回 `MainPID=0` 且退出 0，
  因此 remove 的“运行中检查”在 unit 已不存在时仍幂等。
- **socket 激活语义实测**（构建机 systemd 245，临时 transient 单元，已清理）：`Accept=no` 的服务
  `accept()` 一个连接后退出时，socket 保持 active、service 回到 inactive；第二次连接会再次触发服务
  （日志两次），确认“空闲 0 进程 + 每连接一次激活”成立。同一实验也表明：服务若**不** accept，pending
  连接会让 systemd 反复触发直到 `StartLimitBurst`；helper 的 `serve` 总是先 accept 再处理，因此不会
  出现该循环，而 `StartLimitBurst=60` 是这个场景的兜底（每次成功激活也计入 start rate limit，所以
  批量安装不能被默认的小额度卡住）。
- **手动监听 smoke test**（构建机真实 root，`/tmp` 临时路径，已清理）：`qwq-privileged --socket
  /tmp/... --socket-group root` 启动后 `ping` 返回 `{"ok":true,"version":"0.1.0","uid":0}`，未知 op 与
  非 JSON body 均返回 `VALIDATION_FAILED`，日志只有 op/错误、没有请求体。
- **真实 root publish smoke**（构建机 root，临时插件/staging 根，已清理）：把 0555/0444 的 staging 树
  publish 到 `plugins/alpha/1.2.3` 后，目录 `555`、entrypoint `555`、manifest `444`，全部 `root:root`；
  第二次 publish 返回 `"existing":true`；日志只有 `op=publish id=alpha ok=true`。`/tmp` 目录由脚本
  清理，未安装 systemd 单元、未接触测试机。

### 7.2 并行任务的既有失败

上一轮基线中 `cmd/qwq` 的 `TestRegisterPublicRoutes`（`route count = 52, want 43`）与本任务无关；
本轮最终运行时该测试已由并行的路由/网关任务修复，全包通过。本任务新增的 `cmd/qwq` 代码
（`--privileged-socket` flag、`StagingRoot` 与 `newPrivilegedHelper`）不改变路由表。

## 8. 真实 root/systemd 验证建议（测试机）

1. 安装：二进制放 `/usr/local/bin/qwq-privileged`，unit 放 `/etc/systemd/system/`，tmpfiles 放
   `/usr/lib/tmpfiles.d/qwq.conf`；`systemd-tmpfiles --create && systemctl daemon-reload &&
   systemctl enable --now qwq-privileged.socket`。
2. `systemctl status qwq-privileged.socket` 为 active；`systemctl is-active qwq-privileged.service` 为
   inactive（空闲 0 进程）。
3. ping：`printf '{"op":"ping"}\n' | socat - UNIX-CONNECT:/run/qwq/privileged.sock`，期望
   `{"ok":true,"version":"...","uid":0}`；请求结束后再看 `systemctl is-active qwq-privileged.service`
   应为 inactive。
4. 以 `qwq` 用户跑 `serve-controller --privileged-socket /run/qwq/privileged.sock`，确认启动日志
   `plugin installs use the privileged helper`；直接 `touch /etc/systemd/system/x` 仍应 permission denied。
5. 走一次真实插件安装（controller 以 `qwq` 运行）：
   - `/var/lib/qwq/plugins/<id>/<version>/` 由 root 创建，目录 `0555`、文件 `0444`（entrypoint
     `0555`），内容与包一致；`/var/lib/qwq/staging` 下不再有 `.staging-*`。
   - `/etc/systemd/system/qwq-plugin@<id>.{service,socket}`、`.service.d/10-resources.conf`、
     `/etc/tmpfiles.d/qwq-plugin-<id>.conf`、`/run/qwq/creds/<id>.token` 的属主/权限正确；
     token 是 43 个 base64url 字符、`0600`，`journalctl -u qwq-privileged` 与 controller 日志中都不应
     出现 token 文本。
   - `systemctl is-enabled qwq-plugin@<id>.socket` 为 enabled；`systemctl daemon-reload` 后
     `systemd-analyze verify qwq-plugin@<id>.service` 除了模板占位的 ExecStart 之外不应有新错误。
6. 卸载：确认运行中拒绝（`PRECONDITION_FAILED`），停止后 remove 删除 unit、tmpfiles、token、版本目录，
   `systemctl is-enabled qwq-plugin@<id>.socket` 应为 not-found/disabled（disable 已清理 enable 符号链接），
   再次 remove 仍成功（幂等）。
7. 失败注入：`systemctl stop qwq-privileged.socket` 后安装应得 `UNAVAILABLE`；手工发相对路径/
   `../` 版本目录、超长 body、未知 op 应得 `VALIDATION_FAILED` 且无文件落盘。
8. 加固核对：`systemd-analyze security qwq-privileged.service`（关注 `PrivateNetwork`、`ProtectSystem`、
   `CapabilityBoundingSet`、`SystemCallFilter`）；`ss -xl | grep privileged.sock` 应只有 Unix socket。

## 9. 限制与后续

- 每个 socket 激活只处理一个请求（这是“空闲 0 进程”的代价）：并发安装会排队，由 systemd 为下一连接
  再激活；代码里的并发上限 4 在手动 `--socket` 模式生效，也是将来若改成常驻监听时的硬上限。
- helper 的 `--plugins-root` / `--staging-root` 必须与 controller 的 `--plugins-dir` /
  `--staging-dir` 一致，否则 publish/install 会被拒绝（安全优先）。两个根在 helper 启动时校验
  不得重叠：staging 属于 qwq，plugins 属于 root。
- helper 只接受 token 的 base64（请求行内），不读 argv/环境；token 只写入 helper 内存、请求 JSON 和
  最终 `0600` credential 文件，不落日志/事件/响应。若将来要传更多凭据，应扩展同一 JSON 协议而不是
  加命令行参数。
- **token 的宿主侧消费尚未实现**：仓库目前没有读取 `$CREDENTIALS_DIRECTORY/qwq-token` 并与插件握手
  校验的代码，也没有 DB 列保存 token。`InstallUnit` 每次安装都会生成新 token 并覆盖
  `/run/qwq/creds/<id>.token`；运行中的旧实例在启动时已拿到自己的副本，不受影响，但下一次 start
  会使用新值。等宿主需要校验时，应把 token 与插件实例/代际关联后再决定持久化方式，不能把明文写进
  数据库或日志。
- **publish 的临时目录**：复制在 `<plugins>/<id>/.publish-*` 下完成，成功 rename 后消失；正常错误路径
  会删除。如果 helper 在复制中被 SIGKILL，可能留下一个 `.publish-*` 目录，版本目录本身不会出现
  半成品（rename 原子）。当前没有自动清理这些残留；`RemoveUnit`/人工删除即可，量很小。
- `deployments/polkit/qwq-plugin.rules` 不变：安装走 helper 后，controller 不再需要写 unit 的 polkit 权限；
  start/stop/kill 仍由 polkit 放行。
- **已解决的上一轮阻塞**：版本目录 publish 与 token 都已由 helper/InstallUnit 处理；不再需要把
  `/var/lib/qwq/plugins` 授权给 qwq，也不需要在 controller 内 `install.Staged.Commit`。controller 的
  staging 现在固定为 `/var/lib/qwq/staging`，需要 tmpfiles 或首次 `Extract` 创建（父目录
  `/var/lib/qwq` 已属于 qwq，所以首次安装也能自建）。
- socket 权限只到用户级：`qwq` 用户（controller 与 agent 共用）可调用 helper，插件（DynamicUser）不可。
  如果将来要区分 controller 与 agent，应使用不同的 socket group，而不是把 helper 暴露给更多用户。
