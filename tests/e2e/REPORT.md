# P3 真机端到端报告（1C1G）

> **2026-11-09 夹具改造（ENG-02），新结果待 M1 测试机补录。** 以下 2026-11-02 的记录
> 基于旧夹具：root 进程内驱动 updater、手工预建 `/run/qwq/host/noop` 与假 host.sock、
> 只装 helper unit。新夹具改为：发布包 `install.sh --offline` 安装（sysusers、tmpfiles、
> 全部 unit，controller 以 `User=qwq` 运行），经 HTTPS API 驱动；`TestPluginEndToEnd`
> 断言 host 通道目录由 helper 建（2750 qwq:qwq-p-noop）、host.sock 由 controller 提供、
> 失败的更新（`noop 0.1.3` Initialize 必失败）后仍运行原版本、controller 重启后插件与
> `/run/qwq` 下 socket 都在；`TestControllerEndToEnd` 覆盖 setup-token → setup → 安装/
> 调用 → 更新 → 回滚 → 重启 controller → 模拟主机重启。每个测试以 `uninstall.sh --purge`
> 复原。环境变量：`QWQ_E2E_RELEASE_TAR`、`QWQ_E2E_PKG_V1/V2/BAD`、`QWQ_E2E_TRUST_PUB`
> （不再需要 `QWQ_E2E_BIN_DIR`/`QWQ_E2E_UNITS_DIR`）。`build.sh` 的 GOARCH 默认取构建机架构。

日期：2026-11-02
测试机：Ubuntu 24.04，1 vCPU / 961 MiB，systemd 255
结果：**PASS**，`TestPluginEndToEnd` 35.31s、`TestPluginStartStop100` 100 轮 755.44s，`E2E_EXIT=0`

## 覆盖链路

1. helper socket 激活：`qwq-privileged.socket` active，service 每请求激活后退出
2. `install 0.1.1`：签名包校验 → helper publish（root 0555/0444 版本树）→ 写 unit/credential → daemon-reload → enable socket → start
3. attach：go-plugin Reattach + `GetDescriptor` 版本校验 + `Initialize`/`Start` + `CheckHealth`（`STATUS_SERVING`，`LIFECYCLE_STATE_ACTIVE`）
4. 机械断言：MainPID/starttime、版本树 root 0555/entrypoint 0555/data 0444、credential 0600 43 字节、plugin socket 0600 qwq、bind target
5. `update 0.1.2`：memory preflight 无法读 cgroup 时降级 restart → stop 0.1.1 → publish/install 0.1.2 → start/attach/health → 旧实例 Release
6. `rollback 0.1.1`：`ReinstallUnit` 重新渲染旧 unit → restart → attach/health
7. 新 Runtime `Attach`（模拟宿主重启）→ Ready/Health
8. `Stop` + `Release`；`RemoveUnit(0.1.1/0.1.2)`；清理后无 `qwq-*` unit、无 qwq 用户/组、无 `/run/qwq`、`/var/lib/qwq`、`/opt/qwq`

## 本次暴露并修复

| 问题 | 修复 |
|---|---|
| 插件进程无法执行版本树 | `/var/lib/qwq` 从 0700 改 0711（可穿越、不可写） |
| 插件无法到达 host 通道 | `/run/qwq` 改 0711；helper 渲染 `/run/qwq/link` 0711 target |
| GetDescriptor 版本 0.1.0 与包 0.1.1 不符 | `noop` 增加 `buildVersion` 链接注入，E2E 构建 0.1.1/0.1.2 两个二进制 |
| rollback 启动的仍是新版本 unit | `Installer.ReinstallUnit` + `stepArm`/`restoreOld` 在启动旧版前重渲染 unit |
| 移除第二个版本时 groupdel 失败 | 根因是 helper seccomp 的 `~@privileged` 包含 `@chown`，shadow 写 `/etc/group-`、`/etc/gshadow-` 时的 `fchown` 被 EPERM；unit 改为显式 deny 列表（去掉 `@chown`，保留 `@resources`），E2E 断言 private group 必须由 helper 删除，不再用 root 兜底（见 `cmd/qwq-privileged/REPORT-GROUP.md`） |
| 旧版没有 `manifest.json` 可读 | `ReinstallUnit` 改为接收 updater 已保存的 `Version.Manifest`，不读版本树文件 |

## 100 次启停/强杀基线

`TestPluginStartStop100` 在 1C1G 上安装一次后循环 100 次，每 10 轮 `SIGKILL` 主进程一次：

- 总耗时 **12m22s**；启动/停止各 100 次，其中 10 次强杀。
- 测试进程 FD：**14 → 18**（+4，阈值 +8）；goroutine：**8 → 5**。
- 插件进程峰值 RSS：**17,564 KiB**（阈值 64 MiB）；每轮停止后 systemd `MainPID=0`，无残留 plugin 进程。
- 暴露并修复：
  - `UpdaterRuntime.Stop` 之前只停 service，socket 仍 active，下一次连接会把 service 重新拉起；现在 service + socket 一起停，下一次 Start 由 `Requires=` 重新拉起 socket。
  - plugin unit `StartLimitBurst=3` 会把第 4 次启动判为 `start-limit-hit`；改为 60s 内 120 次，保留 crash-loop 保护，同时允许升级/回滚/基线连续重启。
  - 强杀后 systemd 会按 `Restart=on-failure` 自动重启；基线等待重启完成后显式 stop service+socket，避免 stop 与 restart 竞态。

## 复现

```bash
# 构建机（Linux/Go）
bash tests/e2e/build.sh /root/qwq-dev/e2e-new
# 产物送到测试机后（root）
cd /root/qwq-dev/e2e-new
QWQ_E2E_BIN_DIR=$PWD/bin \
QWQ_E2E_UNITS_DIR=$PWD/units \
QWQ_E2E_PKG_V1=$PWD/packages/noop-0.1.1.qwq \
QWQ_E2E_PKG_V2=$PWD/packages/noop-0.1.2.qwq \
QWQ_E2E_TRUST_PUB=$PWD/key.pub \
./e2e.test -test.v -test.run TestPluginEndToEnd
```

## 残留

- helper 组删除已修复（2026-11-02 复验）：seccomp 放行 shadow 必需的 `fchown` 后，E2E 的 remove 由 helper 成功删除 `qwq-p-noop`，`getent group qwq-p-noop` 为空，journal 无 `failed to remove group`；`sandbox.Remove` 仍保留 warning 作为 shadow 锁冲突的兜底。详见 `cmd/qwq-privileged/REPORT-GROUP.md`。
- 100 次启停/强杀基线已完成；未单独做 OOM 顺序注入。
- HTTP 安装/更新/回滚端点已实现（`internal/api/REPORT-PLUGIN-HTTP.md`），但未做 HTTP→真实 systemd 的端到端联调。
- 测试机的临时 publisher 私钥、staging 和 fixtures 已删除；测试产物不进入仓库。
