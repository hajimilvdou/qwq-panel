# 插件凭据轮换与恢复

状态：已验收，2026-11-20；对应 P0-RT-01 / P1-RT-01。基线 e9ab142，Platform ABI 与已提交迁移不变。

## 边界与已有事实

每个宿主插件只有当前、上一槽两个 SHA-256，明文仍只由既有 helper / sandbox 以 0600 写入受控凭据文件。修复前，`ReinstallUnit` 漏写数据库，`InstallUnit` 单槽替换会切断仍存活旧进程的宿主调用。

认证继续先验真实 peer 的 PID、UID、unit、cgroup；双槽不能代替这些事实，也不能将另一插件或实例的 token 当作本插件凭据。HostSvc 每次 RPC 读取最多两个摘要并恒时比较，错误或重复 token metadata、错误摘要、存储错误均拒绝；不缓存认证结论。

## 同一 saga 的两个槽

采用 Installer 的窄内部凭据生命周期接口，提供是否启用、同事务开始与同事务收口；无数据库的旧测试 installer 保留原行为。`insertSagaTx` 在新 RUNNING saga 与 started 事件的同一事务固定 `prev = current`，只运行一次；恢复及步骤重试不重新抓旧槽。既有 `PluginTokens.Put` 只更新当前槽，故重复安装、重装或补偿不会把原仍存活旧进程的摘要挤出窗口，也不会保留第三个摘要。新 saga 开始时重新固定旧槽，丢弃此前终态留下的旧摘要。

安装、重装共用“生成 → 受控写盘 → 记录当前摘要”的 helper，只有两者都成功才允许推进步骤。任何错误保留原原因并进入既有有界补偿；token 明文用后清理，不写日志、事件或数据库。

HostSvc 仅在该插件确有 RUNNING saga 时接受上一槽；没有运行中 saga 时只接受当前槽。上一槽残留不代表长期授权。首次安装没有原摘要，只有新槽。

## 成功、回滚与失败恢复

正常提交在候选已 Ready/Activate、旧进程 Stop/Release 后，将旧槽清理、活动版本和 saga COMMITTED 放在同一写事务。恢复里的已 committed 收尾复用同一收口，事务失败仍可重试；不在终态之后另开一个“尽量清理”的事务。

凭据补偿在清理候选前用现有 step/error 列记录 `credential_abort/<原失败步骤>` 意图。恢复旧进程成功但终态事务失败时，Recover 继续该补偿，不会回到原 commit 步骤把已停候选写成 ACTIVE；完成后终态仍保留原失败步骤。该私有状态不增加 SQL 迁移或公共 ABI。

回滚与失败恢复先清理候选，再按已有受控 Stop/Release 终止旧版本的残留进程、清掉旧 handle，重新安装旧版本当前凭据并以 readyHandle 启动/Activate。只有实际新进程与文件、数据库当前槽对齐后，才能在 ROLLED_BACK 同事务收口。失败发生在 stop_old 之前也走这条对齐路径；不交换数据库摘要冒充恢复了旧明文，不复用仍持旧 token 的进程后直接清上一槽。

Start/Attach 在 bootstrap 与注册前必须核验版本：至少一个 descriptor 版本或宿主已加载 ExecStart 路径事实可比对，两项均可读时同时匹配。缺失全部证明或事实冲突拒绝；Attach 仅关闭连接，不停止未知进程，Start 只清理本次启动的候选。正向 fixture 构造真实入口与已加载路径，单 unit 的 Attach 也必须精确拒绝另一版本。

补偿失败保留明确 FAILED 和原因，不把未对齐的进程标健康。没有 RUNNING saga 后上一槽不再用于认证；后续新 saga 重新固定窗口，不能复活历史上一槽。每插件现有锁与数据库约束仍串行化安装、升级、回滚和恢复。

## 验证

原代码 RED 证明真实写盘后的 ReinstallUnit 摘要不一致、saga 未固定旧槽和提交收口；随后覆盖 HostSvc 旧/新窗口、坏 peer/跨插件/重复 metadata、实际进程恢复和每个步骤崩溃、收口事务失败与再次 Recover。Root 另验证 Start/Attach 的版本事实缺失与矛盾；假 systemctl 按真实语义保留进程启停前后的已加载 ExecStart，假 Attach 必须精确匹配版本。

Linux 13504 的原凭据范围七包完整通过；扩展至 17源/16Go 后，28319 完整 exit 0：全部凭据与六种版本事实回归、controller/updater/hostsvc/cmd/qwq 四包普通/race/vet/staticcheck、仓库 lint 和宿主构建通过。16Go 格式归档的 SHA、成员、类型、父路径与 token 核验后恢复；Root 独立 P0/P1/P2 复核未见本范围新增阻断项。全部失败和修正依据保留，真实双 VPS 与长时资源验收仍属于项目终验。
