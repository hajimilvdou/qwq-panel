<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# P2-T1 spike 报告：插件拉起路径与本地传输（ADR-0003）

- 日期：2026-11-01
- 范围：`spikes/p2t1/**`（独立 Go 模块，不进 `go.work`）
- 测试机：Ubuntu 24.04.3 LTS，systemd 255.4，kernel 6.8.0-137，cgroup v2，1 vCPU / 961 MiB，与宝塔共存
- 构建机：Ubuntu 20.04（Go 1.27.3），交叉编译 `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`
- 代码：`cmd/agent`（宿主侧最小 agent）、`cmd/plugin`（最小插件）、`internal/echopb`（JSON codec 的 gRPC 服务）、`internal/peercred`（SO_PEERCRED / SO_PEERPIDFD / cgroup 解析）、`systemd/`（单元与 polkit 规则）、`deploy/`（安装、验收、卸载脚本）

## 1. 结论

**方案 A 成立**：`DynamicUser=yes` + `qwq-spike-plugin@<id>.socket`（systemd 创建监听 socket、`SocketUser=qwq-spike-agent`、`SocketMode=0600`）+ 插件在继承的 fd 上提供 gRPC + Agent 用 go-plugin `ReattachConfig` 连接 + 每插件 UDS 反向 Host 通道 + 双向 `SO_PEERCRED`，全部跑通，ADR-0003 的 5 条验收全过（41 项自动断言 0 失败）。

但有三处必须写回 ADR：

1. **go-plugin 的 `plugin.Serve` 不能用于方案 A**。`Serve` 只会自己 `net.Listen` 一个新建 socket（源码见 §6.1），无法接收 systemd 传入的 fd。插件 SDK 必须自己实现「在继承 fd 上 serve gRPC」，只复用 go-plugin 的 **client/Reattach** 一侧。实测这样能用，go-plugin 客户端对缺失的内部服务是容忍的。
2. **`SO_PEERCRED` 在插件 socket 上不能用来识别插件进程**。监听 socket 归 systemd（pid 1）所有，客户端一侧的 `SO_PEERCRED` 返回 **pid 1 / uid 0**（`init.scope`），实测 `peer_pid=1`、`go_plugin_peer_pid=1`。因此「Agent 由对端 PID 读 `/proc/<pid>/cgroup` 确认单元名」在方案 A 下不成立。可行的替代是：**插件身份在 Host 通道上由内核证实**（插件是客户端，agent `accept()` 时拿到真实 pid/uid），再加上 systemd 的 `MainPID`、cgroup 单元名、`/proc/<pid>/stat` 的 starttime 做交叉校验；插件 socket 本身用 `0600`（只有 agent 能连）来授权。
3. **不需要 privileged helper 参与启停**。polkit 规则足以让非 root agent 对 `qwq-spike-plugin@*` 执行 start/stop/restart/kill，且拒绝其它单元（实测 `Interactive authentication required`）。helper 仍然需要，但只用于安装期/渲染期：建组、建目录、装单元、下发 credential、`ExecStartPre` 校验摘要。

另外几个操作性发现（都是实测踩出来的，必须写进 P2）：

- `systemctl kill --kill-whom=all -s SIGKILL` 在 systemd 255 上返回 `Failed to send signal SIGKILL to auxiliary processes: Invalid argument`（进程仍被杀、cgroup 仍被清空）。用 `--kill-whom=main` 干净返回 0，配合单元里的 `KillMode=control-group` 就能清空整个 cgroup。
- `ProtectProc=invisible` 让插件读不到 agent 的 `/proc/<pid>/cgroup`（`ENOENT`），所以**插件侧只能按 ADR 说的只校验 agent 的 UID**，单元名只能由 agent 侧校验。这与 ADR 现有表述一致，但报告里要显式写明原因。
- **`systemctl start <service>`（不碰 socket 单元）也会拿到 fd 3**：只要同名 `.socket` 单元是 active，systemd 会把 `LISTEN_FDS=1` 传给直接启动的 service（实测 `LISTEN_FDS":"1"`）。所以 agent 用 service 单元做 start/stop 是可行的，不需要为了拿 fd 去操作 socket 单元。
- **但 socket 单元不能在其 service 运行时重启**：`systemctl start qwq-spike-plugin@<id>.socket` 会失败并记 `Socket service qwq-spike-plugin@<id>.service already active, refusing.`。正确顺序是「先停 service，再停/起 socket，最后起 service」；`systemctl stop <service>` 也会提示 `its triggering units are still active`，即下一次连接会被 socket 重新拉起（on_demand 的正常语义）。
- **agent 不能缓存 MainPID**。spike 第一版把 `MainPID` 缓存在内存里，运维在带外重启插件后，agent 仍拿旧 pid 去比对，导致插件的 host 上报全部被拒。改成每次上报都读 `systemctl show -p MainPID`（开销可忽略）后恢复正常。P2 的 supervisor 必须以 systemd 为唯一事实来源。

## 2. 测试对象与目录

| 对象 | 值 |
|---|---|
| systemd 单元 | `qwq-spike-agent.service`、`qwq-spike-plugin@.service`、`qwq-spike-plugin@.socket`（实例 `alpha`、`beta`） |
| 系统用户/组 | `qwq-spike-agent`（系统用户）、`qwq-spike-p-alpha` / `qwq-spike-p-beta`（每插件私有组） |
| 二进制 | `/opt/qwq-spike/spike-agent`、`/opt/qwq-spike/spike-plugin`（root:root 0755） |
| 运行时 | `/run/qwq-spike/{plugin/<id>,host/<id>,state,creds,link}` |
| polkit | `/etc/polkit-1/rules.d/qwq-spike.rules` |
| credential | `LoadCredential=spike-token:/run/qwq-spike/creds/%i.token`（root 0600，64 hex 字符） |

传输与身份设计（实测可行的形态）：

```text
systemd(pid 1)  ── 拥有 plugin.sock (0600 agent) ──▶ 插件进程只拿到 fd 3
agent(uid 995)  ── connect(plugin.sock) ──▶ gRPC (go-plugin ReattachConfig, 协议 grpc)
插件            ── connect(/run/qwq-spike/link/host.sock) ──▶ agent 的 HostService
                  ↑ 仅该插件 namespace 内的 BindPaths 能看到这个路径（源目录 2750 + 每插件私有组）

身份：
  插件 → agent：插件看 SO_PEERCRED 的 uid == agent uid（socket 属主），pidfd 可用
  agent → 插件：agent 在 Host 通道 accept() 上拿到真实 peer pid/uid，
                与 systemctl MainPID、/proc/<pid>/cgroup、starttime 交叉校验
  插件 socket：文件 0600 agent，非该 uid 根本无法 connect；进程身份靠 Host 通道 + systemd
```

## 3. 验收证据

以下命令与输出都来自 `deploy/accept.sh`（测试机 root 执行，证据原文在测试机 `/root/qwq-dev/p2t1/evidence.txt`，安全分析全文在 `security.txt`）。汇总：`SUMMARY: PASS=41 FAIL=0`。

### 验收 1：插件 A 无法连接插件 B 的插件 socket 与 host socket

探针由 **A 自己的进程**执行（`Probe` RPC，spike 专用测试钩子，生产 ABI 不能有这种任意路径接口）：

```text
--- plugin alpha probes (executed inside its own sandbox) ---
own-host-bind-mount      /run/qwq-spike/link/host.sock      want_dial=true  dial_ok=true   pass=true
own-host-real-path       /run/qwq-spike/host/alpha/host.sock want_dial=false dial_ok=false pass=true
                         dial_err="dial unix ...: connect: permission denied" stat_err="lstat ...: permission denied"
own-plugin-socket        /run/qwq-spike/plugin/alpha/plugin.sock want_dial=false dial_ok=false pass=true
                         dial_err="dial unix ...: connect: permission denied"
other-plugin-socket:beta /run/qwq-spike/plugin/beta/plugin.sock  want_dial=false dial_ok=false pass=true
other-host-socket:beta   /run/qwq-spike/host/beta/host.sock      want_dial=false dial_ok=false pass=true
                         stat_err="lstat ...: permission denied"
--- plugin beta probes ---  （对称，全部 pass）
PASS: all 5 probes of alpha match expectation
PASS: all 5 probes of beta match expectation
PASS: alpha cannot connect plugin socket of beta / host socket of beta
PASS: beta  cannot connect plugin socket of alpha / host socket of alpha
```

机制与证据：

- 插件 socket：`/run/qwq-spike/plugin/<id>/` 是 root 0711，`plugin.sock` 是 `qwq-spike-agent:qwq-spike-agent 0600`；别的插件 uid 不同，`connect` 直接 `EACCES`。
- host socket：源目录 `/run/qwq-spike/host/<id>` 是 `qwq-spike-agent:qwq-spike-p-<id>` **2750**，socket 0660（继承目录的组）。插件只通过 `BindPaths=/run/qwq-spike/host/%i:/run/qwq-spike/link` 看到自己那一个；真实路径 0700 不可穿越，所以连自己的真实路径都进不去（上面 `own-host-real-path` 也被拒），只有 bind mount 里的 `/run/qwq-spike/link/host.sock` 可连。
- 第一次尝试把宿主目录建成 0700（agent 属主）时，插件即使有 bind mount 也被 `EACCES`（bind mount 不改变 inode 权限），这就是改成「私有组 + 2750 + 0660」的原因，已记录为模板要求。

### 验收 2：非 root Agent 能连接插件，`SO_PEERCRED` 双向校验通过

agent 侧状态（`/run/qwq-spike/state/alpha.json`，节选）：

```json
{
  "plugin_id": "alpha", "unit": "qwq-spike-plugin@alpha.service",
  "main_pid": 1613106, "plugin_uid": 62580,
  "plugin_cgroup": "/system.slice/system-qwq\\x2dspike\\x2dplugin.slice/qwq-spike-plugin@alpha.service",
  "plugin_start_time": 638961896, "generation": "d853015d80144327",
  "plugin_socket_peer_is_systemd": true, "peer_pid": 1, "peer_uid": 0, "peer_pidfd": true,
  "host_verified": true, "host_peer_pid": 1613106, "host_peer_uid": 62580,
  "host_peer_unit": "qwq-spike-plugin@alpha.service", "host_main_pid_match": true,
  "host_generation": "d853015d80144327", "unit_match": true,
  "reattach_pid": 1613106, "go_plugin_peer_pid": 1, "go_plugin_peer_uid": 0,
  "go_plugin_peer_unit": "init.scope", "agent_peer_verified": true, "agent_peer_unit_visible": false,
  "echo": {
    "peer_pid": 1613098, "peer_uid": 995, "peer_unit": "",
    "peer_unit_err": "open /proc/1613098/cgroup: no such file or directory",
    "expected_agent_uid": 995, "peer_pidfd": true,
    "host_report_ok": true, "host_generation": "d853015d80144327",
    "credential_sha256": "7bf7f973e475bb22"
  }
}
```

双向校验的结论：

- **插件 → agent**：插件在 Echo 里报告 `peer_uid=995`（即 `qwq-spike-agent` 的 uid，与 socket 属主一致）、`peer_pid=1613098`、pidfd 可用；不匹配时返回 `PermissionDenied`（实现是 fail-closed：先要求 `agentUID != 0` 且 `cred.UID == agentUID`）。`peer_unit` 为空是**预期**的：`ProtectProc=invisible` 使插件看不到其它 uid 的 `/proc` 条目（`ENOENT`）。
- **agent → 插件**：在 Host 通道上，agent `accept()` 到的是插件进程本身，`peer_pid == MainPID`、`peer_uid == 插件动态 uid`、`peer_unit == qwq-spike-plugin@alpha.service`、pidfd 可用；请求里自报的 pid/uid 只作交叉校验（不一致就拒绝）。插件 socket 上的 `SO_PEERCRED` 是 systemd（pid 1 / uid 0 / `init.scope`），**不作为插件身份依据**，这一点已写进 ADR 修改建议。
- 非 root agent（uid 995）能以 0600 socket 连上插件：`host service listening ... agent_uid=995`、`plugin attached ... plugin_socket_peer_pid=1` 且 RPC 成功。

`systemd-analyze security` 未覆盖这一项；对应单元属性：

```text
$ systemctl show -p MainPID -p ControlGroup -p DynamicUser qwq-spike-plugin@alpha.service
MainPID=1613106
ControlGroup=/system.slice/system-qwq\x2dspike\x2dplugin.slice/qwq-spike-plugin@alpha.service
DynamicUser=yes
```

### 验收 3：`systemctl restart qwq-spike-agent` 后 Reattach 成功、generation 不丢

```text
before: generation=d853015d80144327 main_pid=1613106 starttime=638961896
$ systemctl restart qwq-spike-agent.service
after:  generation=d853015d80144327 main_pid=1613106 starttime=638961896 agent_pid=1613525
PASS: generation unchanged across agent restart (d853015d80144327)
PASS: plugin process start time unchanged (no restart)
PASS: new agent re-derived the same identity and generation
$ jq . /run/qwq-spike/state/alpha.host.json
{ "count": 1, "agent_pid": 1613525, "peer_pid": 1613106,
  "peer_unit": "qwq-spike-plugin@alpha.service", "accepted": true,
  "generation": "d853015d80144327" }
PASS: plugin re-reported to the new agent process
```

- generation = `sha256(unit|MainPID|/proc/<pid>/stat 第22字段)[:16]`，全部来自 systemd + 内核，重启 agent 后重算一致。
- 插件进程没有重启（starttime 不变），新 agent 通过 `ReattachConfig{Addr: unix socket, Pid: MainPID, Protocol: grpc}` 重新接上，并重新拿到 Host 通道上报（`agent_pid` 从 1613098 变成 1613525，插件侧日志 `host report accepted ... agent_pid:1613525`）。
- go-plugin 的 `ReattachConfig.Pid` 语义见 §6.2：它只用于「等进程退出」和 `Kill`，不参与身份校验；必须传真实 `MainPID`（激活后才有值）。

### 验收 4：`systemctl kill` 后 cgroup 内无残留进程

```text
$ systemctl stop qwq-spike-plugin@alpha.socket
$ systemctl kill --kill-whom=main -s SIGKILL qwq-spike-plugin@alpha.service
$ systemctl show -p MainPID -p ActiveState -p SubState qwq-spike-plugin@alpha.service
MainPID=0
ActiveState=failed
SubState=failed
$ cat /sys/fs/cgroup/system.slice/system-qwq\x2dspike\x2dplugin.slice/qwq-spike-plugin@alpha.service/cgroup.procs
cat: ...: No such file or directory        # cgroup 已被 systemd 回收
$ pgrep -a -f /opt/qwq-spike/spike-plugin
1606602 /opt/qwq-spike/spike-plugin -id beta   # 只有另一个插件
PASS: MainPID is 0 after kill
PASS: plugin cgroup has no processes left
PASS: no plugin process survived
```

- `KillMode=control-group` + `--kill-whom=main` 就能清空整个 cgroup。
- `--kill-whom=all` 在本机 systemd 255 上返回 `Failed to send signal SIGKILL to auxiliary processes: Invalid argument`（实测同样杀干净，但退出码非 0）。建议 ADR/实现写成 `systemctl stop`（正常路径）或 `systemctl kill --kill-whom=main`（强杀路径）。

### 验收 5：`systemd-analyze security` 分数

```text
$ systemd-analyze security qwq-spike-plugin@alpha.service
...
✓ SystemCallFilter=~@resources    System call allow list defined for service, and @resources is not included
✓ SystemCallFilter=~@privileged   System call allow list defined for service, and @privileged is not included
✓ RestrictAddressFamilies=~AF_(INET|INET6)  Service cannot allocate Internet sockets
✓ CapabilityBoundingSet=~CAP_MAC_*          Service cannot adjust SMACK MAC
✓ UMask=                                     Files created by service are accessible only by service's own user
→ Overall exposure level for qwq-spike-plugin@alpha.service: 0.6 SAFE :-}
```

**初值 0.6（SAFE）**，建议 CI 门槛 `<= 1.0`（回归到 0.8 以上就要看是哪条变差了）。完整表格见测试机 `/root/qwq-dev/p2t1/security.txt`。

## 4. 额外度量

### 冷启动与 RPC 延迟（本机 1 vCPU；多次运行的量级，未做分布统计）

| 指标 | alpha | beta |
|---|---|---|
| `socket unit start` → 首个 health RPC 成功（`cold_start_ms`） | 35–133 ms | 17–164 ms |
| 同上直到 `Echo` 返回（含 go-plugin Reattach，`echo_call_ms`） | 90–182 ms | 54–219 ms |
| health 尝试次数 | 1 | 1 |

`socket_unit_started_ms`（`systemctl start` 本身）11–72 ms。区分两种情形：**真正冷启动**（service 未运行，由 socket 激活）落在 **89–164 ms**；**service 已在运行时的 reattach**（agent 重启）低到 **17–35 ms**。连同首个 `Echo`（含 go-plugin Reattach）整体在 **100–250 ms** 量级，`on_demand` 冷启动对 UI 可接受（ADR §6.4 要求显示进度与超时，这里是预算依据）。

### 空闲内存（插件启动 2 s 后，单实例）

```text
plugin MainPID=1613106 cgroup=/system.slice/system-qwq\x2dspike\x2dplugin.slice/qwq-spike-plugin@alpha.service
cgroup memory.stat: anon 1585152  file 8192  kernel 675840  kernel_stack 81920  pagetables 110592  slab 339424
memory.current=2301952  memory.peak=2568192  memory.max=50331648
/proc/<pid>/status: VmRSS 11488 kB  VmHWM 11488 kB  RssAnon 1548 kB  RssFile 9908 kB  Threads 6
agent:  memory.current=3403776  VmRSS 14216 kB  Threads 6
```

- 插件**计费内存** `memory.current` ≈ 2.2 MiB（anon 1.5 MiB + kernel 0.65 MiB），峰值 2.4 MiB；而 `VmRSS` 11.2 MiB 主要是可执行文件的可共享 file-backed 页（`RssFile 9.9 MiB`），cgroup 没有把它算进 `memory.current`（`file 8192`、`file_mapped 0`）。
- 结论：1 核 1G 预算里，每个 Go+gRPC 插件约 **2.2 MiB 计费 + 11 MiB 物理足迹**；`MemoryMax=48M` 绰绰有余（实测占 4.6%），`GOMEMLIMIT=40MiB` 不构成约束。ADR §13.1 的预算应按「计费内存」和「RSS 足迹」两列写，preflight 读 `memory.current` 时要知道它不含共享可执行页。
- 线程 6 个、`pids.current=6`、`TasksMax=32` 足够。

## 5. 方案 A 的实现要点（可直接进 P2 设计）

1. **插件 socket 由 systemd 建**：`.socket` 单元 `ListenStream=%t/qwq-spike/plugin/%i/plugin.sock`、`SocketUser=qwq-spike-agent`、`SocketMode=0600`、`Service=qwq-spike-plugin@%i.service`、`RemoveOnStop=yes`；目录由安装器建（root 0711）。插件只拿到 fd 3（`LISTEN_FDS=1`、`LISTEN_FDNAMES=qwq-spike-plugin@alpha.socket`）。
2. **插件在 fd 上 serve**：`os.NewFile(3)` → `net.FileListener` → `grpc.NewServer(...)`；注册 `grpc_health_v1`（服务名 `""` 和 `"plugin"` 都置 SERVING，因为 go-plugin `Ping()` 查的是 `"plugin"`）+ 业务服务；SIGTERM 时 `GracefulStop`。
3. **插件只用 uid 认 agent**：启动时 `stat(host.sock)` 取属主 uid/gid 作为期望 agent 身份（生产上应由安装器渲染到配置或用 `LoadCredential` 下发），每次 host 连接用 `SO_PEERCRED` 校验；`SO_PEERPIDFD` 拿到的 pidfd 可用于无 PID 复用窗口的存活校验。
4. **Host 通道**：agent 为每个插件监听 `/run/qwq-spike/host/<id>/host.sock`（socket 0660，组 `qwq-spike-p-<id>`），插件单元用 `BindPaths` 只把该目录映射到 `/run/qwq-spike/link`；源目录 2750 + 私有组，其它插件既穿越不了也连不上。
5. **Host 服务端按内核事实鉴权**：`accept()` 得到的 `SO_PEERCRED` → `/proc/<pid>/cgroup` 单元名必须等于 `qwq-spike-plugin@<id>.service`、pid 必须等于 systemd `MainPID`、请求里自报的 pid/uid/id 只作交叉校验。
6. **generation**：`sha256(unit|MainPID|starttime)[:16]`，agent 重启后重算一致；插件自报的启动时间只用于比对。
7. **凭据**：`LoadCredential=spike-token:%t/qwq-spike/creds/%i.token`（root 0600）；实测插件 `Environment` 只有 `GOMEMLIMIT=40MiB`，`/proc/<pid>/environ` 里也没有 token（只有 `CREDENTIALS_DIRECTORY`），`systemctl show -p LoadCredential` 只显示 `[unprintable]`。
8. **启停权限**：polkit 规则按 `subject.user == "qwq-spike-agent"`、`action.id == org.freedesktop.systemd1.manage-units`、`unit =~ ^qwq-spike-plugin@[a-z0-9-]+\.(service|socket)$`、`verb ∈ {start,stop,restart,try-restart,reload,kill}` 放行；实测 agent 能 start/stop 插件的 service 与 socket（socket 在其 service 运行时会被 systemd 以 `already active, refusing` 拒绝，属语义限制而非权限），但 `systemctl start qwq-spike-agent.service`、`systemctl stop ssh.service` 都被拒（`Interactive authentication required`）。
   - 局限：静态 polkit 规则只能按名字模式限定，不能白名单「已安装的插件 id」。生产要么由 helper 按已安装集合生成规则文件，要么规则改成「单元名 + 一个 agent 可读的已安装清单」由 helper 维护。这一点建议写进 ADR。

## 6. go-plugin v1.8.0 的问题与对策（源码证据）

许可证：`github.com/hashicorp/go-plugin v1.8.0` 是 **MPL-2.0**（文件级 copyleft）。我们只是链接/调用，不复制其源码；MPL-2.0 §3.3 允许把 Larger Work 以 AGPL-3.0-only 分发，二者兼容。`go-hclog` MIT、`grpc` Apache-2.0、`golang.org/x/sys` BSD-3-Clause、`protobuf` BSD-3-Clause。

### 6.1 `plugin.Serve` 无法在继承 fd / 已有 listener 上工作

```go
// server.go:495 Serve()
	listener, err := serverListener(unixSocketConfigFromEnv())   // server.go:547
// server.go:799 serverListener_unix()
	tf, err := os.CreateTemp(unixSocketCfg.socketDir, "plugin")  // 自建临时文件
	path := tf.Name(); ... os.Remove(path)
	l, err := net.Listen("unix", path)                          // 自己 listen
```

`ServeConfig` 没有 listener/fd 字段（只有 `GRPCServer` 回调用于配置 `*grpc.Server`），`PLUGIN_UNIX_SOCKET_DIR` 只影响它**自己**创建 socket 的目录。所以：

- 方案 A 下 **插件侧不能用 `plugin.Serve`**，必须自己 `grpc.NewServer().Serve(ln)`。
- `plugin.Serve` 的握手（stdout 打印 `core|proto|network|addr|grpc`）也一并用不上；Reattach 本来就不看握手。
- 对策：P2-T2 的 SDK 提供 `ServeOnListener(ln net.Listener, services ...)`，不复用 `plugin.Serve`；`PLUGIN_UNIX_SOCKET_DIR` 不参与。

### 6.2 `ReattachConfig` 的 `Pid` 语义

```go
// client.go:299 type ReattachConfig{Protocol, ProtocolVersion, Addr, Pid, ReattachFunc, Test}
// client.go:973 reattach(): reattachFunc = cmdrunner.ReattachFunc(pid, addr)
// internal/cmdrunner/cmd_reattach.go
	conn, err := net.Dial(addr.Network(), addr.String())  // 先探活一次，失败 → ErrProcessNotFound
	return &CmdAttachedRunner{pid: pid, process: p}
func (c *CmdAttachedRunner) Wait(_ context.Context) error { return pidWait(c.pid) }
func (c *CmdAttachedRunner) Kill(_ context.Context) error { return c.process.Kill() }
// internal/cmdrunner/process.go:14 pidWait(): 每秒 kill(pid,0) 轮询
```

- `Pid` **只用于「等进程退出」和 Kill**，不参与身份校验；`ReattachFunc` 会用 `net.Dial` 探一次地址（这一步就会触发 socket activation）。
- 传 `Pid=0` 时 `pidWait(0)` 把 0 当成「一直活着」（`kill(0,0)` 是进程组语义），所以必须传真实 `MainPID`；而 socket 激活场景下 `MainPID` 只有在**首次连上之后**才有值 → 我们的顺序是：`systemctl start <socket>` → 连一次触发激活 → 轮询 `systemctl show -p MainPID` 直到非 0 → 再用该 Pid 调 `plugin.NewClient`。
- **`Client.Kill()` 会 `process.Kill()`（SIGKILL）插件**。生产代码绝不能对 Reattach 的 client 调 `Kill()`；停插件只走 `systemctl stop/kill`。我们只在退出时调 `ClientProtocol.Close()`（关连接，不发信号）。
- `SecureConfig` 与 `Reattach` 互斥（`client.go:55`）、`AutoMTLS` 与 Reattach 互斥、`GRPCBrokerMultiplex` 与 Reattach 互斥（`client.go:59`）——与 ADR 一致。

### 6.3 gRPC 客户端会额外拉起 broker / stdio（可容忍）

```go
// grpc_client.go:835 newGRPCClient()
	brokerGRPCClient := newGRPCBrokerClient(conn); go func(){ _ = brokerGRPCClient.StartStream() }()
	stdioClient, err := newGRPCStdioClient(doneCtx, ..., conn)   // Unimplemented → 仅 warn
	cl := &GRPCClient{Conn: conn, Plugins: c.config.Plugins, controller: plugin.NewGRPCControllerClient(conn)}
```

- 插件不实现 `plugin.GRPCStdio` 时客户端只打一条 `stdio service not available` 警告，不影响 RPC（实测）。
- 插件不实现 `plugin.GRPCController` 时，只有 `ClientProtocol.Close()` 可能报错（我们忽略），不影响 attach。
- `GRPCClient.Ping()` 查 `grpc_health_v1` 的 `Service: "plugin"`（`grpc_client.go:127`、`grpc_server.go:26`），所以 SDK 必须注册 health 并把 `"plugin"` 置 SERVING（我们这么做了，`health_attempts=1`）。
- `Dispense(name)` 只是调用我们注册的 `GRPCPlugin.GRPCClient(ctx, broker, conn)`（`grpc_client.go:869`），没有额外 RPC、没有握手、没有 magic cookie —— 这就是为什么 Reattach 路径能和一个「非 plugin.Serve」的服务端正常协作；反过来也说明 **cookie 不提供任何安全性**，身份只能来自传输层。

### 6.4 `GRPCDialOptions` 可以覆盖拨号器

`ClientConfig.GRPCDialOptions` 追加在默认 dialer 之后，我们用它塞入自定义 `grpc.WithContextDialer`，从而在**真实**的 go-plugin 连接上取 `SO_PEERCRED`（结果同样是 pid 1，证明 §1 第 2 条不是测量误差）。

### 6.5 其它

- socket 激活下每个新连接都会触发一次服务启动；服务连续崩溃时 systemd 会「被连接驱动」地反复拉起（实测崩溃期间每 3 s 一次）。ADR §6.4 的 quarantine 必须包含「停掉 `.socket` 单元」，否则退避逻辑在 socket 单元这一层是失效的。
- `.socket` 的 `ListenStream` 父目录需要存在；`/run` 是 tmpfs，重启后消失。生产要么用 `tmpfiles.d`，要么验证 `.socket` 单元上的 `RuntimeDirectory=`（本次未验证，留作 P2-T5 的待办）。

## 7. 对 ADR-0003 的修改建议（diff 形式）

```diff
@@ 决策 3（不依赖 AutoMTLS/SecureConfig/GRPCBrokerMultiplex）
    - 完整性：安装时校验摘要；包目录归 root 且只读（`ProtectSystem=strict`）；`ExecStartPre` 由 helper 再校验一次入口文件摘要。
    - Host Service：不走 go-plugin broker。Agent 为每个插件单独监听一个 UDS（`/run/qwq/host/<id>.sock`），通过 `BindPaths=` 只映射进该插件的挂载命名空间，其他插件看不到。
+   - 插件侧不使用 go-plugin 的 `plugin.Serve`：它总是自己 `net.Listen` 一个新建 socket，无法接收 systemd 传入的 fd。
+     SDK 自己实现「在继承 fd 上 serve gRPC」，只复用 go-plugin 的客户端/Reattach 路径（源码证据见 P2-T1 spike 报告 §6.1）。
+   - Host Service：Agent 为每个插件单独监听一个 UDS（`/run/qwq/host/<id>/host.sock`，0660，组 `qwq-p-<id>`），
+     通过 `BindPaths=/run/qwq/host/<id>:/run/qwq/link` 只映射进该插件的挂载命名空间；父目录 0700 不可穿越，
+     同一目录内的其它插件 socket 即使同级组也访问不到（每插件一个组）。

@@ 决策 4（对端认证）
-   4. **对端认证（必须）**：双方在每个连接上校验 `SO_PEERCRED`。Agent 由对端 PID 读 `/proc/<pid>/cgroup` 得到单元名，确认是预期插件；插件 SDK 只接受 Agent 的 UID。内核 ≥ 6.5 时用 `SO_PEERPIDFD` 消除 PID 复用窗口。插件身份与 generation 只从这里得出，不信任消息字段。
+   4. **对端认证（必须）**：双方在每个连接上校验 `SO_PEERCRED`，但两侧能证明的事实不同：
+      - 插件 socket 的监听端由 systemd（pid 1）持有，连接方一侧的 `SO_PEERCRED`/`SO_PEERPIDFD` 返回的是 systemd，
+        **不能**用来识别插件进程（P2-T1 实测 `peer_pid=1`、`go_plugin_peer_pid=1`）。插件 socket 用 `0600` + Agent 属主做授权。
+      - **插件身份在 Host 通道上由内核证实**：插件是连接方，Agent 在 `accept()` 后读 `SO_PEERCRED` 得到真实 pid/uid，
+        要求 pid == systemd `MainPID`、`/proc/<pid>/cgroup` 单元名 == `qwq-plugin@<id>.service`，并用 `/proc/<pid>/stat` 的 starttime
+        与 systemd 事实一起算 generation。请求里自报的 pid/uid/id 只作交叉校验，不作为身份来源。
+      - 插件 SDK 只接受 Agent 的 UID（socket 属主或安装器渲染的配置给出）；`ProtectProc=invisible` 下插件读不到 Agent 的
+        `/proc/<pid>/cgroup`，所以插件侧不做单元名校验。
+      - 内核 ≥ 6.5 时用 `SO_PEERPIDFD` 消除 PID 复用窗口（Host 通道上是真正有用的）。
+      - Agent 不得调用 go-plugin 的 `Client.Kill()`：Reattach 模式下它会对进程发 SIGKILL；停止/强杀只走 `systemctl stop|kill`。

@@ 决策 5（方案 A 的落地细节）
     | A（倾向） | `DynamicUser=yes`；配套 `qwq-plugin@<id>.socket` 由 systemd 预先创建监听 socket，`SocketUser=qwq-agent`、`SocketMode=0600`；插件 SDK 在继承的 fd 上提供 go-plugin 的 gRPC 服务 | 不留系统用户；socket 权限由 systemd 保证；顺带支持 `on_demand` 冷启动 | go-plugin 在非 `Serve()` 创建的 listener 上运行、Reattach 到 socket 激活单元时的 Pid 语义 |
-    两个方案都必须满足：其他插件无法连接、Agent 无需 root 即可连接、Agent 重启后能 Reattach。**禁止让所有插件共用一个 socket 组。**
+    两个方案都必须满足：其他插件无法连接、Agent 无需 root 即可连接、Agent 重启后能 Reattach。**禁止让所有插件共用一个 socket 组。**
+    P2-T1 结论：A 成立，但需要「每插件一个私有组」来共享 Host 通道（`qwq-p-<id>`），
+    Host 目录 2750 + socket 0660，插件单元 `SupplementaryGroups=qwq-p-<id>`，`BindPaths` 映射到 `/run/qwq/link`；
+    插件 socket 目录 root 0711、socket 0600 Agent。systemd 255 + DynamicUser 实测可用。

@@ 验收标准（P2-T1）
-2. 非 root 的 Agent 能连接插件，`SO_PEERCRED` 双向校验通过。
+2. 非 root 的 Agent 能连接插件；插件侧 `SO_PEERCRED` 校验 Agent UID 通过；Agent 侧在 Host 通道上以 `SO_PEERCRED` 证实
+   插件 pid/uid/cgroup 单元并通过（插件 socket 上的 `SO_PEERCRED` 在 socket 激活下指向 systemd，不能用于此判定）。
-4. `systemctl kill qwq-plugin@<id>` 后插件 cgroup 内无残留进程。
+4. `systemctl kill --kill-whom=main -s SIGKILL qwq-plugin@<id>`（或 `systemctl stop`）后插件 cgroup 内无残留进程；
+   注意 `--kill-whom=all` 在 systemd 255 上会返回 `Invalid argument`（进程仍被杀），不要把它当作断言依据。
```

补充建议（不改 ADR 文本，写进 P2-T5/P2-T2）：

- 单元模板的 `ExecStartPre` 摘要校验、credential 下发、每插件组/目录创建都属于 helper 职责；Agent 只做 start/stop/restart/kill。
- polkit 静态规则只能按 `qwq-plugin@[a-z0-9-]+` 模式限定，不能限定「已安装 id」；如要收紧，由 helper 生成规则或改用 helper IPC。

## 8. 给 P2-T2（插件 SDK）的具体输入

1. `ServeOnListener(ln, opts)`：`net.FileListener(fd)`（systemd 激活）或自建 listener（开发态）；注册 `grpc_health_v1`（`""`、`"plugin"` 置 SERVING）；`grpc.ServerOption` 里挂 `peercred` 传输凭据；SIGTERM → `GracefulStop`。
2. 不要引入 `plugin.Serve`；不要依赖 `PLUGIN_UNIX_SOCKET_DIR`、magic cookie、`GRPCStdio`、`GRPCController`。
3. Host 客户端：连接 `/run/qwq/link/host.sock`（或安装器渲染的路径），每条连接校验 `SO_PEERCRED` 的 uid == agent uid（从 socket 属主或配置取），可选 pidfd；断线重连 500 ms–2 s 退避（agent 重启后必须在数秒内重新上报）。
4. 不要信任任何自报身份；`GetDescriptor`/generation 由宿主在 Host 通道上给出。
5. 不要把插件 stdout/stderr 作为协议通道；日志走 journald。
6. host 通道不可用时插件要「能起、能自检失败、不要 busy loop」——实测 500 ms 重试会刷日志，SDK 应有退避与单次告警。

## 9. 给 P2-T5（单元模板）的具体输入

must-have（实测有效）：

```ini
# plugin@.service
DynamicUser=yes
SupplementaryGroups=qwq-p-%i
LoadCredential=spike-token:%t/qwq-spike/creds/%i.token
BindPaths=/run/qwq-spike/host/%i:/run/qwq-spike/link
KillMode=control-group
MemoryMax=48M
MemoryHigh=43M
GOMEMLIMIT=40MiB            # Environment=
OOMScoreAdjust=500
# S2 模板全部指令可用；含 ProtectProc=invisible、ProcSubset=pid、
# SystemCallFilter=@system-service ~@privileged @resources + EPERM、空 CapabilityBoundingSet
```

```ini
# plugin@.socket
ListenStream=/run/qwq-spike/plugin/%i/plugin.sock
SocketUser=qwq-spike-agent
SocketMode=0600
Service=qwq-spike-plugin@%i.service
RemoveOnStop=yes
```

注意事项：

- 插件 socket 目录：root 0711（可穿越、不可列举）；宿主目录：`agent:qwq-p-<id>` 2750；socket 0660。
- **不要**给 Agent 单元加 `ProtectProc`/`ProcSubset`（它必须读插件 `/proc/<pid>/cgroup`、`status`）；插件单元必须加。
- Agent 单元在 `ProtectSystem=strict` 下需要 `ReadWritePaths=/run/qwq-spike`（host socket、state）。
- `PrivateNetwork=yes` + `RestrictAddressFamilies=AF_UNIX` 与 UDS 兼容，不影响 `BindPaths`；`MemoryDenyWriteExecute=yes` 对 Go 无影响（实测）。
- Agent 通过 `/usr/bin/systemctl`（D-Bus）操作单元，规则见 polkit 文件；实现上也可换成直接 D-Bus 调用，鉴权模型不变。
- 每插件组 `qwq-p-<id>` 由安装器创建；卸载时删除；不要复用同一个组给多个插件。
- **启停顺序**：安装/开机时只 start `.socket` 单元（on_demand）；agent 要 eager 启动时直接 `systemctl start <service>`（fd 会被传）；停止用 `systemctl stop <service>`；要重建 socket 必须先停 service。`systemctl start <socket>` 在 service 运行时一定会失败。
- **MainPID 不缓存**：每次需要时 `systemctl show -p MainPID`（或 D-Bus 属性），systemd 是唯一事实来源；带外重启后缓存会立刻过期。

## 10. 卸载验证（`deploy/uninstall.sh` 结尾输出，原文）

```text
== verification: remaining qwq-spike objects ==
absent:  unit file qwq-spike-agent.service
absent:  unit file qwq-spike-plugin@.service
absent:  unit file qwq-spike-plugin@.socket
absent:  unit registered qwq-spike-agent.service
absent:  unit registered qwq-spike-plugin@alpha.service
absent:  unit registered qwq-spike-plugin@alpha.socket
absent:  user qwq-spike-agent
absent:  group qwq-spike-agent
absent:  group qwq-spike-p-alpha
absent:  group qwq-spike-p-beta
absent:  group qwq-spike-link
absent:  polkit rule
absent:  binaries dir /opt/qwq-spike
absent:  runtime dir /run/qwq-spike
absent:  credentials dir alpha
absent:  credentials dir beta
absent:  processes
absent:  cgroup alpha
absent:  cgroup slice
--- loaded units matching qwq-spike* ---
--- systemd failed units matching qwq-spike* ---
--- end ---
```

`accept.sh` 跑了 6 轮、`measure.sh` / `killprobe.sh` / `socketprobe.sh` 各 1 轮，最后又做了一次干净的 install→uninstall 循环，`install.sh`/`uninstall.sh` 可重复执行。早期设计遗留的 `qwq-spike-link` 组也已经被 `uninstall.sh` 清掉并纳入检查；最终测试机上没有留下任何 `qwq-spike*` 单元、用户、组、文件、进程或 cgroup。

## 11. 未覆盖 / 风险

- 只在 1 vCPU / 961 MiB、无内存压力的机器上跑了 2 个实例；没有做「接近 `MemoryMax` 时 OOM 顺序」的实测（`OOMScoreAdjust` 只验证了写入，未验证内核选择）。
- 没有验证蓝绿/双实例并发、`CPUQuota` 限流、`LimitNOFILE` 打满、插件 fork 子进程后的 cgroup 清理（spike 插件不 fork）。
- 没有验证 `.socket` 单元用 `RuntimeDirectory=` 自建目录（现在靠安装器建目录 + tmpfs）；重启机器后 `/run` 为空，需 `tmpfiles.d` 或 `RuntimeDirectory=`，P2-T5 要定。
- polkit 只验证了「按用户 + 单元名模式」；没验证 polkit 不在/被停掉时的降级（此时 agent 启停会失败，需要 helper 兜底或 `qwq doctor` 报错）。
- 没有验证 `ExecStartPre` 摘要校验、包目录只读、`ProtectSystem=strict` 下的升级替换（属于 P2-T4/T5）。
- 单次测量，未做统计分布；延迟数据只作量级参考。
