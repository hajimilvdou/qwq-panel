# ADR-0030：精确派发中的秘密 scope

状态：已接受，2026-11-20 完成实施与受影响范围验证；关联 P0-CORE-05 与 X3。范围覆盖共享 HostSecretsService，不修改 Platform ABI。

## 决定

RevealSecret 请求的 purpose 仍为审计文本，不决定存储 owner/purpose。宿主从已验签的 manifest 授予列表提取 config/operation 精确 scope，通过内部 SecretRevealer seam 传入；插件不能提供或扩大这个列表。

两种 scope 都要求真实本地 executor、RUNNING、未取消/过期、精确插件/实例/节点，以及当前 RBAC、委派策略、权限模式和原有效审批。复用 operations 的 ResolveDispatched 和 runtime proof 检查，不只信任持久 RUNNING 行。现有资源能力入口仍要求非空精确 subject；秘密入口从真实操作构造完整目标，允许原操作没有可选 subject。

- config：已授予 scope 与原操作 Capabilities 都须含精确 `secret.reveal:config`；存储固定 `plugins/<plugin_id>` + `plugin.config`。保护既有 core.apply 配置路径。
- operation：已授予 scope 与原操作 Capabilities 都须含精确 `secret.reveal:operation`；引用必须是原受保护 Args 的完整引用对象，并位于创建时 ArgsSchema 标记的敏感字段；存储固定同插件 owner + `plugin.operation`。外部预埋引用继续拒绝。

声明 `secret.reveal:operation` 的 operation/plan 在创建时将原 schema 与 Action 一起写入私有 `action_meta` JSON：保留旧 flat Action 布局，追加 `args_schema` 旁字段。其他操作不增加每行 schema 副本；公开 Action 的 `json:"-"` 保持不变，公共 DTO 不输出该字段。所有 schema 读取来自原持久快照和真实 executor proof，不从当前目录重新取值。旧无 schema 行继续可按原 config scope 使用，operation scope 因无法证明原敏感字段成员而拒绝；不猜测或回填当前插件 schema。

宿主只把满足上述条件的存储 purpose 传入 RevealOwnedAnyPurpose。其他 owner、用途、未知引用与非原参数成员均拒绝，不开放批量明文或客户端自报 owner。读取后再次重查原派发及当前授权，取消/撤权/替换 executor 后清空本次明文并拒绝返回。

HostSecretsService 保留 peer/token、配额、审计先于返回及审计失败清零。内部 SecretRevealer 接口同步更新全部实现/fake；没有向旧无归属 Reveal 降级的旁路。core.xray manifest 及 core.apply 已声明 config scope，仍不新增 operation scope。

## 资源与验证

不新增 goroutine、缓存、FD、后台任务或依赖。多两次短暂的当前派发/授权核验与一次既有 schema walker 检查，参数深度及大小沿用现有边界；解密明文在任何后续失败时清理。

插件原 schema 沿用 Catalog.loadSchema 的 64 KiB 上限；仅声明操作级秘密能力的记录保存该副本，config-only 与其他宿主/插件操作不增加 schema 存储。Operation 与 Plan 共用同一私有编码器和解码器，不另建 SQL 列、索引或缓存。

覆盖两个 scope 正向、互不替代、无授予/无声明、错 owner/purpose、非原参数成员/未标记字段、伪持久 RUNNING、invoke/job、无 subject、当前撤权/取消/结束、读中撤权、配额与审计失败。所有执行与格式在 Linux；成功后独立 P0/P1/P2 复核并本地集成。

2026-11-20：真实派发/历史失败回归、四包普通、七包 race/vet/staticcheck、仓库 lint 与 Controller 构建通过；额外覆盖创建后目录 schema 变更、旧无 schema 行拒绝与公共 JSON 不泄漏。16源SHA及14Go格式成员受检取回，原失败记录保留。完整日志与独立复核索引：`.cache/sdd/reports/ROOT-operation-secret-progress-20261118.md`。
