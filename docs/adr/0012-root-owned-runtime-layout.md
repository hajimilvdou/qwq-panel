# ADR-0012：root 拥有的运行时与插件目录布局

- 状态：已接受（Accepted，2026-11-09）。由审查任务卡 PRIV-01 实施，PRIV-03/04/05 与 PLG-06 在同一布局上继续
- 关联：ARCH §10、§12；ADR-0003（插件沙箱）；审查任务卡 PRIV-01、PRIV-03、PRIV-04、PRIV-05、PLG-06

## 背景

root helper（`qwq-privileged`）的攻击者模型是"以 `qwq` 身份执行代码的进程"。旧布局里 helper 写入的 `/run/qwq/{plugin,link,creds}` 与 `/var/lib/qwq/plugins` 都挂在 qwq 拥有、无 sticky 位的父目录下：qwq 可以把这些 root 子目录 rename 走、放同名符号链接，而 helper 按路径调用 `RemoveAll`/`Chmod`/`Rename`，只对最后一级做 `Lstat`。结果是 root 递归删除或 chmod 任意目录，并可经竞态把文件写进 `/etc/systemd/system/<unit>.d/` 获得 root 代码执行。

## 决策

### 1. 目录布局

| 路径 | 属主 | 权限 | 创建者 |
|---|---|---|---|
| `/var/lib/qwq` | qwq:qwq | 0700 | tmpfiles / `StateDirectory=` |
| `/var/lib/qwq/staging` | qwq:qwq | 0700 | tmpfiles |
| `/var/lib/qwq-plugins` | root:root | 0755 | tmpfiles（从 `/var/lib/qwq/plugins` 迁出） |
| `/var/lib/qwq-plugin-data` | root:root | 0711 | tmpfiles（2026-11-14 专用插件数据根） |
| `/var/lib/qwq-plugin-data/<id>/default` | 插件动态 UID | 0700 | systemd `StateDirectory=`；DynamicUser 私有映射由 systemd 管理 |
| `/var/lib/qwq-privileged/creds` | root:root | 0700 | tmpfiles（PRIV-05 使用） |
| `/run/qwq` | root:root | 0711 | tmpfiles |
| `/run/qwq/plugin`、`/run/qwq/link` | root:root | 0711 | tmpfiles |
| `/run/qwq/host` | qwq:qwq | 0750 | tmpfiles；controller 唯一可写的运行时目录 |
| `/run/qwq/host/<id>` | qwq:qwq-p-\<id\> | 2750 | helper 安装时 + 每插件 tmpfiles（PRIV-04） |

`/var/log/qwq` 删除：没有进程写它，日志只走 journald。controller unit 不再使用 `RuntimeDirectory=`（PRIV-03）。

规则：helper 写入的每棵树，其祖先链全部属于 root 且组与其他用户不可写；qwq 能写的目录（`/var/lib/qwq`、`staging`、`/run/qwq/host`）里 helper 只做 fd 相对的、逐项校验的操作。

### 2. 代码层纵深防御

`internal/sandbox/trusted.go` 提供唯一的 `OpenTrustedRoot`/`TrustPolicy.Open`：校验路径与每一级祖先（真实目录、属主 root、无 g/o 写位），打开 `*os.Root` 后再确认句柄与校验的 inode 相同。helper 的 publish/remove/install 与 `sandbox.Installer` 的所有写操作都相对该句柄进行；`os.Root` 拒绝逃出根的符号链接。祖先链不合格时 helper 拒绝工作（fail-closed），不会退回按路径操作。

`TrustPolicy` 的零值是生产策略（uid 0，校验到 `/`）；测试通过字段把属主放宽为当前用户、终点放宽为 `t.TempDir()`。该字段只来自 root 控制的配置，请求无法改变它。

### 3. helper 的 `/etc` 写权限

`ReadWritePaths` 仍包含整个 `/etc`：shadow 工具在 `/etc` 下建锁文件与临时文件，只列出 `/etc/group`、`/etc/gshadow` 不足以让 `groupadd` 工作。第 2 条保证 qwq 无法经由任何可达路径把 helper 的写操作引到 `/etc`。收窄方案留待测试机实测（待 M1）。

### 4. 迁移

升级时安装脚本（DEP-02）在停服状态下：若 `/var/lib/qwq/plugins` 存在则 `mv` 到 `/var/lib/qwq-plugins`，运行 `systemd-tmpfiles --create`，并重新渲染全部插件 unit（unit 中的 `ExecStart`/`verify-entrypoint` 路径随之更新）。

## 后果

2026-11-14 实施补充：宿主数据根保持 0700。插件持久目录从该树分离，helper 的 `UnitSpec.DataDir` 仅允许 `/var/lib/qwq-plugin-data/<本 UnitSpec.ID>/default`，不能指向其他插件或任意 `/var/lib` 子树。原 X2 布局在真实部署前不再使用；已有旧数据的升级须停止插件并完成明确迁移，安装器前置拒绝忽略旧数据。真实动态 UID 遍历和私有映射仍须 X6/X10 验收。

- 旧布局的主机在迁移前 helper 会拒绝 publish/install（`/run/qwq` 属主为 qwq）。这是有意的 fail-closed。
- controller 的 `--plugins-dir` 与 helper 的 `--plugins-root` 默认值同步改为 `/var/lib/qwq-plugins`。
