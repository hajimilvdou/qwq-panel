# ADR-0003：插件拉起路径与本地传输认证

- 状态：Accepted（P2-T1 spike 已验证方案 A；结论见文末）
- 日期：2026-11-01
- 关联：ADR-0001 A03、A08、A12；架构审查 S1、S2、S3

## 背景

- `qwq-agent` 以普通用户运行，不能把子进程切换到其他 UID，也不能给子进程套 systemd sandbox；go-plugin 默认由父进程直接 exec 子进程。
- go-plugin `ClientConfig` 文档：`AutoMTLS` 不能与 `Reattach` 同用；`SecureConfig`（可执行文件校验和）不能与 `Reattach` 同用；`GRPCBrokerMultiplex` 不支持 Reattach。而宿主重启后要靠 Reattach 恢复插件。
- systemd 的 `Environment=` 会经 D-Bus 暴露给非特权客户端，不能用来传凭据。

## 决策

1. **由 systemd 拉起**：每个插件对应模板单元 `qwq-plugin@<id>.service`。单元文件归 root、随宿主安装包提供；资源限制等 drop-in 由 `qwq-privileged` 根据已校验的 manifest 渲染。Agent 只能对 `qwq-plugin@*` 执行 start/stop/kill（polkit 规则按单元名和动作限定，或经 privileged helper），不能定义单元内容。
2. **统一连接路径**：首次启动和宿主重启恢复都用 `ReattachConfig` 连接插件 socket。进程身份以 systemd 的 MainPID 与 cgroup 归属为准，不做自定义的 PID 复用判断。停止和强杀用 `systemctl stop/kill`，按 cgroup 清理全部子进程。
3. **不依赖 go-plugin 的 AutoMTLS、SecureConfig、GRPCBrokerMultiplex**：
   - 完整性：安装时校验摘要；包目录归 root 且只读（`ProtectSystem=strict`）；`ExecStartPre` 由 helper 再校验一次入口文件摘要。
   - 插件侧不使用 go-plugin 的 `plugin.Serve`：它总是自己 `net.Listen` 一个新建 socket，无法接收 systemd 传入的 fd（P2-T1 源码证据见 `spikes/p2t1/REPORT.md` §6.1）。SDK 自己实现“在继承 fd 上 serve gRPC”，只复用 go-plugin 的客户端/Reattach 路径。
   - Host Service：不走 go-plugin broker。Agent 为每个插件单独监听一个 UDS（`/run/qwq/host/<id>/host.sock`，0660，属组 `qwq-p-<id>`），通过 `BindPaths=/run/qwq/host/<id>:/run/qwq/link` 只映射进该插件的挂载命名空间；父目录 0700 不可穿越。禁止多个插件共用一个组。
4. **对端认证（必须）**：双方在每个连接上校验 `SO_PEERCRED`，但两侧能证明的事实不同（P2-T1 实测）：
   - 插件 socket 的监听端由 systemd（pid 1）持有，连接方一侧的 `SO_PEERCRED`/`SO_PEERPIDFD` 返回 **systemd（pid 1、uid 0、`init.scope`）**，不能用来识别插件进程。插件 socket 用 `0600` + Agent 属主做授权。
   - **插件身份在 Host 通道上由内核证实**：插件是连接方，Agent 在 `accept()` 后读 `SO_PEERCRED` 得到真实 pid/uid，要求 `pid == systemd MainPID`、`/proc/<pid>/cgroup` 的单元名 == `qwq-plugin@<id>.service`，并用 `/proc/<pid>/stat` 的 starttime 与 systemd 事实一起算 generation。请求里自报的 pid/uid/id 只作交叉校验，不作为身份来源。
   - 插件 SDK 只接受 Agent 的 UID（socket 属主或安装器渲染的配置给出）；`ProtectProc=invisible` 下插件读不到 Agent 的 `/proc/<pid>/cgroup`，所以插件侧不做单元名校验。
   - 内核 ≥ 6.5 时用 `SO_PEERPIDFD` 消除 PID 复用窗口（在 Host 通道上真正有用）。
   - Agent 不得调用 go-plugin 的 `Client.Kill()`：Reattach 模式下它会对插件进程发 SIGKILL；停止/强杀只走 `systemctl stop|kill`。`MainPID` 不得缓存，每次以 systemd 为唯一事实来源。
5. **插件 socket 的访问控制（P2 spike 二选一）**：

   | 方案 | 做法 | 优点 | 待验证 |
   |---|---|---|---|
   | A（倾向） | `DynamicUser=yes`；配套 `qwq-plugin@<id>.socket` 由 systemd 预先创建监听 socket，`SocketUser=qwq-agent`、`SocketMode=0600`；插件 SDK 在继承的 fd 上提供 go-plugin 的 gRPC 服务 | 不留系统用户；socket 权限由 systemd 保证；顺带支持 `on_demand` 冷启动 | go-plugin 在非 `Serve()` 创建的 listener 上运行、Reattach 到 socket 激活单元时的 Pid 语义 |
   | B（备选） | 安装时创建固定用户 `qwq-p-<hash>`；helper 在 `ExecStartPre` 创建私有 socket 目录并设置 ACL 只允许 Agent | 完全沿用 go-plugin 的 `Serve()` | tmpfs ACL 内核支持、卸载时的 UID 回收与数据归属 |

   两个方案都必须满足：其他插件无法连接、Agent 无需 root 即可连接、Agent 重启后能 Reattach。**禁止让所有插件共用一个 socket 组。**

   P2-T1 结论：**方案 A 成立**，且不需要 privileged helper 参与启停（polkit 的单元名模式规则足够）；helper 仍需要，但只在安装/渲染期（建组、建目录、装单元、下发 credential、`ExecStartPre` 校验摘要）。落地细节：每插件一个私有组 `qwq-p-<id>`；插件 socket 目录 root 0711、socket `qwq-agent` 0600；Host 目录 `agent:qwq-p-<id>` 2750、socket 0660，插件单元加 `SupplementaryGroups=qwq-p-<id>`；停止用 `systemctl stop`，强杀用 `systemctl kill --kill-whom=main -s SIGKILL`（systemd 255 上 `--kill-whom=all` 会返回 `Invalid argument`，进程仍会被杀，但不要拿它做断言）。
6. **凭据传递**：环境变量只传实例 ID、socket 路径、`GOMEMLIMIT` 这类非机密值。短期凭证在连接建立后经已认证的 socket 下发，或用 `LoadCredential=`（systemd ≥ 247）。
7. **资源与沙箱**：drop-in 设置 `MemoryHigh`（≈0.9×上限）、`MemoryMax`、`CPUQuota`、`TasksMax`、`LimitNOFILE`、`OOMScoreAdjust`（插件为正值，宿主为负值）；`Environment=GOMEMLIMIT=≈0.85×上限`。默认沙箱模板见架构审查 S2，CI 用 `systemd-analyze security` 设分数门槛。

## 后果

- 插件运行时只支持带 systemd 的 Linux；完整沙箱需要 systemd ≥ 247，更低版本按 `qwq doctor` 的探测结果降级（第三方插件默认拒绝安装）。
- 宿主安装包要带 polkit 规则或 helper 的 IPC；P2 开头先做 spike，结论写回本 ADR。
- 开发机是 Windows 时，P2 起的任务必须在 Linux 测试环境中完成。

## spike 验收标准（P2-T1）

1. 插件 A 进程无法连接插件 B 的插件 socket 与 host socket（连接被拒或文件不可见）。
2. 非 root 的 Agent 能连接插件；插件侧 `SO_PEERCRED` 校验 Agent UID 通过；Agent 侧在 Host 通道上以 `SO_PEERCRED` 证实插件 pid/uid/cgroup 单元并通过（插件 socket 上的 `SO_PEERCRED` 在 socket 激活下指向 systemd，不能用于此判定）。
3. `systemctl restart qwq-agent` 后 Agent 能 Reattach 到仍在运行的插件，调用不丢失 generation 信息。
4. `systemctl kill --kill-whom=main -s SIGKILL qwq-plugin@<id>`（或 `systemctl stop`）后插件 cgroup 内无残留进程。
5. 记录 `systemd-analyze security qwq-plugin@<id>.service` 的分数，作为 CI 门槛初值。

## P2-T1 结论（2026-11-01，测试机 Ubuntu 24.04 / systemd 255 / cgroup v2）

方案 A 已跑通，自动化断言 41 PASS / 0 FAIL，完整证据与命令见 `spikes/p2t1/REPORT.md`。要点：

- 冷启动（socket activation → 首个 health RPC）89–164 ms；已运行时的 Reattach 17–35 ms。
- 插件计费内存 `memory.current` ≈ 2.3 MiB（`VmRSS` 11.5 MiB，其中 9.9 MiB 是可共享的 file-backed 页）；Agent ≈ 3.4 MiB。
- `systemd-analyze security` 分数 **0.6 SAFE**，CI 门槛建议 `<= 1.0`。
- 插件 socket 的 `SO_PEERCRED` 指向 systemd，这是方案 A 的固定事实；插件身份改由 Host 通道证实（见决策 4）。
- `MainPID` 不缓存；`systemctl start <service>` 在 socket 单元 active 时也会拿到 fd 3；socket 单元不能在对应 service 运行时重启，顺序是“停 service → 停/起 socket → 起 service”。
- 未覆盖：OOM 顺序、`CPUQuota`、蓝绿并发、插件 fork 子进程、polkit 缺失时的降级、`RuntimeDirectory=` 与 tmpfiles 的选择（P2-T5 定）。
