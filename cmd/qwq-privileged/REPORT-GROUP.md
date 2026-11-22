# qwq-privileged 沙箱内 groupadd/groupdel 失败：根因与修复

日期：2026-11-02
测试机：Ubuntu 24.04.3 LTS，1 vCPU / 961 MiB，systemd 255 (255.4-1ubuntu8.18)
构建机：Ubuntu 20.04，3 vCPU（Go 工具链，见 `scripts/remote.env`）
结论：**已修复并复验**。根因是 helper 的 seccomp 拒绝列表 `~@privileged` 把 `@chown` 一并拒绝，
而 shadow 的 `groupadd/groupdel` 在改写 `/etc/group`、`/etc/gshadow` 时必须 `fchown()` 备份文件；
`fchown` 返回 EPERM 后 shadow 放弃写库。与 `ReadWritePaths=/etc`、`setgroups/setgid/setuid` 无关。
该缺陷同样会让**首次安装**的 `groupadd` 失败（旧 E2E 夹具预先用 root 建好了组，掩盖了这一点）。

## 1. 症状与旧证据（修复前）

1C1G 真机 E2E 的 remove 阶段（2026-11-02 09:53，修复前的 unit）在 journal 中留下：

```
Nov 02 09:53:16.633769 ... qwq-privileged[1639965]: ...
Nov 02 09:53:16.633769 racknerd-d38043e groupdel[1640019]: failed to remove group qwq-p-noop from /etc/gshadow
Nov 02 09:53:16.633806 racknerd-d38043e groupdel[1640019]: failed to remove group qwq-p-noop from /etc/group
Nov 02 09:53:16.633824 racknerd-d38043e groupdel[1640019]: failed to remove group qwq-p-noop
Nov 02 09:53:16.7098xx groupdel[1640021]: （同样的三行）
Nov 02 09:53:16.7787xx groupdel[1640024]: （同样的三行）        # RemovePluginGroup 的 3 次重试
```

同一台机器上，测试进程（root，**不在** helper 沙箱里）执行 `groupdel qwq-p-noop` 成功：

```
Nov 02 09:53:19.699171 ... groupdel[1640164]: group 'qwq-p-noop' removed from /etc/group
Nov 02 09:53:19.703589 ... groupdel[1640164]: group 'qwq-p-noop' removed from /etc/gshadow
Nov 02 09:53:19.707154 ... groupdel[1640164]: group 'qwq-p-noop' removed
```

说明失败只发生在 helper 沙箱内。journal 里 `groupadd` 从未失败，是因为 E2E 夹具
`tests/e2e/main_test.go` 的 `prepareHost` 先用 root 执行 `groupadd --system --force qwq-p-noop`；
helper 里的 `groupadd --force` 对已存在的组是空操作，所以没有暴露同样的写失败。

## 2. 根因定位（探针证据）

### 2.1 探针方式

把仓库里的 `deployments/systemd/qwq-privileged.service` **原样**复制到测试机，仅去掉
`ExecStart=*/Type=*/Restart=*/Timeout*/StartLimit*/Requires=*/After=*/Description=*/Documentation=*`
（这些是启动方式，不是沙箱属性），其余属性逐行转成 `systemd-run --property=...`，以 oneshot
运行 `groupadd`/`groupdel`；随后从 journal 读取 shadow 的 stderr 与退出码。完整属性如下（共 34 条）：

```ini
UMask=0022
MemoryMax=32M
TasksMax=16
Environment=GOMAXPROCS=2
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
ProtectSystem=strict
ReadWritePaths=/etc /run/qwq /var/lib/qwq/plugins
ReadOnlyPaths=-/var/lib/qwq/staging
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources        # 仅这一行按实验替换
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_SETGID CAP_SETUID
AmbientCapabilities=
NoNewPrivileges=yes
KeyringMode=private
```

执行命令（每个探针使用独立组名，结束后 root 清理）：

```bash
props=(--property=...上文各条...)
systemd-run --unit="qwq-probe-$name" --wait --collect --property=Type=oneshot \
  "${props[@]}" /bin/bash -c \
  "groupadd --system --force qwq-p-$name; echo GROUPADD_RC=\$?; \
   getent group qwq-p-$name; groupdel qwq-p-$name; echo GROUPDEL_RC=\$?"
journalctl -u "qwq-probe-$name" --no-pager -o cat
```

### 2.2 二分结果

| 探针 | 与完整沙箱的差异 | groupadd | groupdel | 结论 |
|---|---|---|---|---|
| `full` | 无 | rc=10，`failure while writing changes to /etc/group`；`failed to add ... to /etc/gshadow` | rc=6 `does not exist` | 复现 |
| `nofilter` | 去掉两行 `SystemCallFilter` | rc=0 | rc=0 | 过滤器是触发项 |
| `nopriv` | 只保留 `@system-service` 允许表（去掉 deny） | rc=0 | rc=0 | 允许表本身足够 |
| `chown` | deny 改为 `~@chown` | rc=10，同 full | 组不存在 | `@chown` 即可复现 |
| `res` | deny 改为 `~@resources` | rc=0 | rc=0 | `@resources` 无关 |
| `chownonly` | deny 改为 `~chown`（单个 syscall） | rc=0 | rc=0 | shadow 不用 `chown(2)` |
| `fchown` | deny 改为 `~fchown fchownat` | rc=10，同 full | 组不存在 | 精确到 `fchown` |
| `allow` | 保留 `~@privileged @resources`，并额外 `SystemCallFilter=fchown` | rc=10，同 full | 组不存在 | **allow 不能覆盖 deny，必须改窄 deny 列表** |
| `fixed` | 第 4 节的修复列表 | rc=0，`group added to /etc/group|gshadow` | rc=0，`removed from /etc/group|gshadow` | 修复生效 |

关键点：在这些探针里 `/etc` 始终是 `ReadWritePaths` 且 `ProtectSystem=strict` 不变，`res` 探针证明
`ReadWritePaths=/etc` 没有问题；`fchown` 探针把范围缩到单个 syscall 后仍复现，说明是 seccomp，
不是 `setgroups/setgid/setuid`，也不是 `/etc` 写保护。

### 2.3 strace 证据

宿主机（无沙箱）上 `groupdel`/`groupadd` 的真实调用序列：

```
openat(AT_FDCWD, "/etc/group-", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 7
fchown(7, 0, 0)                 = 0          # root:root
fchmod(7, 0644)                 = 0
write(7, "root:x:0:\n...", ...) = 854
...
openat(AT_FDCWD, "/etc/gshadow-", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 7
fchown(7, 0, 42)                = 0          # root:shadow（Ubuntu 上 shadow 的 gid 是 42）
fchmod(7, 0640)                 = 0
...
rename("/etc/group+", "/etc/group") = 0
rename("/etc/gshadow+", "/etc/gshadow") = 0
```

在 `~@chown` 沙箱里（为让 strace 自身能跑，诊断时额外 `--property=SystemCallFilter=ptrace`；
该放行**不在**修复中），得到直接错误：

```
fchown(6, 0, 0) = -1 EPERM (Operation not permitted)
```

`fchown` 属于 systemd 的 `@chown`，而 `@chown` 是 `@privileged` 的子集；因此
`SystemCallFilter=~@privileged @resources` 实际拒绝了 `fchown`。seccomp 在能力检查之前返回
EPERM（`SystemCallErrorNumber=EPERM`），shadow 的 commonio 写备份文件失败，于是打印
`failure while writing changes to /etc/group` 并放弃整个 group/gshadow 更新。

### 2.4 为什么不只是卸载

`groupadd` 与 `groupdel` 走同一套 shadow commonio（`/etc/group-`、`/etc/gshadow-`、`fchown`）。
在没有预建组的机器上，helper 的首次安装会在 `CreatePluginGroup` 就失败；旧 E2E 因为夹具预建组
（对已存在组 `groupadd --force` 不写文件）而一直 PASS，属于测试盲区。

## 3. 修复

`deployments/systemd/qwq-privileged.service`：把宽泛的 `~@privileged @resources` 展开成
**`@privileged` 去掉 `@chown`**，`@resources` 继续拒绝。允许表 `@system-service` 与其余沙箱属性完全不变。

```ini
SystemCallFilter=@system-service
SystemCallFilter=~@clock @module @raw-io @reboot @swap @resources
SystemCallFilter=~_sysctl acct bpf capset chroot fanotify_init fanotify_mark nfsservctl open_by_handle_at pivot_root quotactl quotactl_fd setdomainname setfsuid setfsuid32 setgroups setgroups32 sethostname setresuid setresuid32 setreuid setreuid32 setuid setuid32 vhangup
```

安全性说明：

- 允许表仍是 `@system-service`，没有整体放开过滤；`ptrace` 等不在允许表内（诊断时只有临时探针额外放行）。
- `setgroups`、`setuid`、`capset`、`chroot`、`bpf`、模块加载、`reboot`、`@raw-io`、`@swap`、`@clock`、
  `@resources` 等继续拒绝。复验探针里 `ionice`（`ioprio_set`，属于 `@resources`）仍返回 EPERM，
  `setpriv` 在激活 capabilities（`capset`）时仍被拒绝。
- `fchown` 本来就需要 `CAP_CHOWN`；unit 的 `CapabilityBoundingSet` 早已包含 `CAP_CHOWN`
  （用于 debug listener 的 chown），因此这里只是允许一个已有能力对应的 syscall，没有新增能力。
- `ReadWritePaths=/etc` 保持不变（shadow 需要整个 `/etc` 可写来放锁文件/临时文件）。

其他改动：

- `internal/sandbox/install.go`：仅补充注释，说明 shipped unit 必须允许 shadow 的 `fchown`；
  组删除的 warning 兜底保留（锁冲突等仍可能发生），但不再是正常路径。
- `tests/e2e/main_test.go`：删除 `requireRemoved` 里的 root `groupdel` 兜底。现在若 helper 没删掉
  `qwq-p-noop`，测试直接失败，不会再把沙箱回归掩盖成“清理成功”。
- `cmd/qwq-privileged/REPORT.md`、`tests/e2e/REPORT.md`：同步文档中“groupdel 仍失败”的旧结论。

## 4. 验证

### 4.1 修复后的 unit 探针（测试机，systemd-run）

用第 3 节的列表替换 deny 行后，完整沙箱内：

```
+ groupadd --system --force qwq-p-fixed
group added to /etc/group: name=qwq-p-fixed, GID=985
group added to /etc/gshadow: name=qwq-p-fixed
new group: name=qwq-p-fixed, GID=985
+ echo GROUPADD_RC=0
GROUPADD_RC=0
+ getent group qwq-p-fixed
qwq-p-fixed:x:985:
+ groupdel qwq-p-fixed
group 'qwq-p-fixed' removed from /etc/group
group 'qwq-p-fixed' removed from /etc/gshadow
group 'qwq-p-fixed' removed
+ echo GROUPDEL_RC=0
GROUPDEL_RC=0
```

### 4.2 真机 E2E（1C1G，root）

构建：`bash tests/e2e/build.sh /root/qwq-dev/e2e-groupfix`（构建机，独立 `src-groupfix`），
校验 `sha256sum -c SHA256SUMS` 全部 OK 后上传测试机。

运行：

```bash
cd /root/qwq-dev/e2e-groupfix
QWQ_E2E_BIN_DIR=$PWD/bin QWQ_E2E_UNITS_DIR=$PWD/units \
QWQ_E2E_PKG_V1=$PWD/packages/noop-0.1.1.qwq \
QWQ_E2E_PKG_V2=$PWD/packages/noop-0.1.2.qwq \
QWQ_E2E_TRUST_PUB=$PWD/key.pub \
./e2e.test -test.v -test.run '^TestPluginEndToEnd$'
```

结果：**PASS**，`E2E_EXIT=0`，`--- PASS: TestPluginEndToEnd (35.71s)`。关键日志：

```
=== step 1: install 0.1.1
=== step 2: update 0.1.2
=== step 3: rollback 0.1.1
=== step 4: attach to the running instance
=== step 5: stop and remove
cleanup verified: no qwq units, directories, users or groups remain
```

`requireRemoved` 在 `env.cleanup()` **之前**执行，此时 `getent group qwq-p-noop` 已为空；
测试不再调用 root `groupdel`，仍通过。

### 4.3 journal 中的 groupdel 成功与去重

```
10:28:14.514970 qwq-privileged[1644003]: ... msg="serving a socket-activated request"
10:28:15.063972 groupdel[1644057]: group 'qwq-p-noop' removed from /etc/group
10:28:15.068842 groupdel[1644057]: group 'qwq-p-noop' removed from /etc/gshadow
10:28:15.073865 groupdel[1644057]: group 'qwq-p-noop' removed
10:28:15.573999 qwq-privileged[1644003]: ... msg="privileged request" op=remove id=noop ok=true duration=1.054s
```

同窗口（10:27:43–10:28:19）内 `failed to remove group` / `failure while writing` 命中数为 **0**；
`op=remove` 两次均 `ok=true`（第一次是保留 unit 的版本目录删除，第二次才是包含组删除的最终移除）。
E2E 日志里也没有 `plugin unit removed with warnings`（controller 只在 `RemoveResult.Warnings` 非空时打印）
或任何 `groupdel` 失败字样；仅有的两条 WARN 是 cgroup v2 `memory.current` 读取失败的既有降级。

### 4.4 清理后状态

```
systemctl list-unit-files 'qwq*'   → 0 unit files
ls /etc/systemd/system/qwq*        → No such file
ls /etc/tmpfiles.d/qwq.conf        → No such file
ls /run/qwq /var/lib/qwq /var/log/qwq /opt/qwq /usr/local/bin/qwq-privileged → 均不存在
getent group 'qwq*'                → 无
getent passwd 'qwq*'               → 无
```

临时探针 unit（`qwq-probe-*`）已停止/`reset-failed` 并删除；测试机上的探针脚本、fixtures
（`/root/qwq-dev/e2e-groupfix`）、window/journal 临时文件已删除。`/root/qwq-dev` 整体删除
（其中的 `bin/`、`p2t1/` 是 11-01 遗留的旧产物，也一并清理）；测试机上已无任何 qwq 文件。

## 5. 复现链（供以后回归）

1. 取任意 Linux + systemd 主机，root，创建 `/run/qwq`、`/var/lib/qwq/plugins`、`/var/lib/qwq/staging`。
2. 复制 `deployments/systemd/qwq-privileged.service`，去掉 `ExecStart/Type/Restart/Timeout*/StartLimit*/Requires/After/Description/Documentation`，其余转成 `systemd-run --property`。
3. 用这些属性跑 `groupadd --system --force qwq-p-probe && groupdel qwq-p-probe`。
   - 旧 deny（`~@privileged @resources`）：`groupadd` rc=10，`failure while writing changes to /etc/group`。
   - 新 deny（本文第 3 节）：两步均 rc=0。
4. 若复现失败，直接跑 `tests/e2e`：新断言会在组残留时失败，而不是用 root 兜底。

## 6. 残余风险

- deny 列表是 systemd 255 `@privileged` 去掉 `@chown` 的快照。将来 systemd 给 `@privileged` 增加新
  syscall 时不会自动被拒绝；允许表 `@system-service`、`CapabilityBoundingSet` 与 `NoNewPrivileges`
  仍是主要边界。升级 systemd 后建议用 `systemd-analyze syscall-filter @privileged` 复核一次。
- helper 进程现在可以调用 `fchown`（以及同组的 `chown/fchownat/lchown`），但仍受 `CAP_CHOWN` 和
  `ReadWritePaths` 限制；helper 没有暴露任意 chown 的操作。若追求更窄的 syscall 面，可以只保留
  `fchown`、把 `chown/lchown/fchownat` 列进 deny（本次 strace 显示 shadow 在 amd64 上只用 `fchown`），
  代价是不同 shadow/发行版实现变化时需要再次调整；当前选择整组 `@chown` 以保持兼容。
- E2E 夹具仍预建 `qwq-p-noop`，因此 E2E 覆盖的是 **groupdel** 路径；`groupadd` 由本文的
  systemd-run 探针覆盖。若要把首次安装也纳入真机 E2E，需要调整 `prepareHost` 的 hostDir 准备顺序
  （预建组是 host 通道目录 chown 的前置条件），建议后续单独做。
- `sandbox.Remove` 对组删除仍保留 warning 兜底与 3 次重试：shadow 锁冲突等情况下组可能短暂残留，
  下一次 uninstall 会重试；但正常路径已不再触发。
- `/etc` 在 helper 命名空间内仍是整体可写（shadow 需要锁文件和临时文件），本次未进一步收窄。
