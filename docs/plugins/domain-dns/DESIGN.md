# 域名与 DNS 模块实施设计

- 依据：Accepted 的 [首期准备设计](../../design/proxy-prerequisites.md) 与 [首期代理设计](../../design/proxy-first-release.md)。
- 实施目录：`internal/prerequisites/{dns,names,store}`；独立业务插件计划为 `domain.dns`。
- 交付阶段：DNC-1 为 DNS 安全执行基础；DNC-2 为证书资源、generation、授权绑定与有界续期；DNC-3 为真实受控后端、能力 RPC、插件页面及集成接线。阶段测试不代表真实 DNS 或 CA 验收。

## 已实现边界

DNS 执行器只接受宿主确认的 provider、zone、scope revision 和 caller，写入仅允许 A、AAAA、CNAME、TXT。提供商接口绑定固定适配器和私有凭据，不接受 API URL、请求模板、任意文件路径或通用秘密揭示。域名以 IDNA 规则规范化，并按 DNS 标签边界判断 zone。

完整 zone 快照参与 expected_revision。非首期记录类型只读入内部快照，以检测 CNAME 与同名 MX 等记录冲突，不暴露其修改 operation。修改、删除还必须匹配原记录内容指纹。提供商返回数据需重新校验，不能因为 API 返回成功就直接发布 applied。

## 写前日志与恢复

每个 zone 的当前提交与有界收据保存为同一 CAS 状态，复用插件 KV 的 expected revision 语义。状态后端缺失或 CAS 失败时不能发送 DNS 变更。日志先保存 submitted，再发送一次提供商请求；请求不自动重发。

提供商返回的记录 ID 在后续查询前持久化。写后读取确认变更后，日志转 applied；明确的拒绝可转 rejected。超时、取消、写结果丢失、最终状态保存失败均保留待对账证据。相同 attempt 只读对账；不同请求不能借同一个 attempt 或覆盖 zone 中的未知提交。查询与写入都有限制时间，收据数量和 zone 记录数量有硬上限。

完整快照与写前复核可以检测多数外部修改。提供商没有条件写 API 时，读取与提交之间仍存在外部写入窗口；真实适配器必须紧邻提交再次读取目标记录，不能把本地 CAS 描述成提供商原子事务。

## DNS-01 归属与清理

challenge 绑定 owner、证书资源、attempt 和授权 zone。生成的私有归属标记用于支持原子标记的提供商；实际返回的记录 ID 是另一种归属证据。仅凭新增同名同值 TXT 不能证明所有权。

Cloudflare 的真实适配器计划在新建记录时原子写入受控 comment 标记。阿里云若新建响应的记录 ID 丢失，且未完成可核验的归属标记，不会猜测记录所有者；返回 outcome_unknown 并保留对账状态。此限制需要页面明确显示，不能以删除同名 TXT 解决。

清理只针对已确认的该次记录 ID，并校验记录完整指纹。外部修改、其他 owner 或证书的 attempt 均拒绝自动删除。清理也先占用 CAS 日志，避免多进程重复发送删除。成功、失败与取消都会进入有界清理；凭据撤销或清理失败保留日志用于告警。未清理的 challenge 不因到期而丢弃归属证据。

## 传播检查

解析器由宿主配置，插件不能提供解析服务器地址。一次检查必须同时包含权威与递归 DNS 来源及采样时间；缺少来源、重复来源、格式错误均不能报告 ready。TXT 检查允许同名其他 challenge 共存；A、AAAA、CNAME 要求目标值一致。AAAA 目标不一致单独报告。

等待传播使用现有 fake/system clock，查询最多五次，默认三次；遵守 Retry-After 和总时间上限。每次查询重新检查授权，取消或撤权后不继续查询。

## 后续宿主接线

新能力服务独立版本化，复用 P6 host UDS、身份链、OperationResolver、限流和审计。共享接线文件需要先协调，冻结 Platform ABI v1 不增加字段。证书私钥、DNS token 和 ACME 账户密钥由宿主按 exact scope 代用；`domain.dns` 与 `tls.certificates` 插件只持有资源状态和公开视图。

真正的 Cloudflare / 阿里云适配器、权威解析后端、ACME DNS-01、generation materialize、续期 service actor 和模块页面尚未在 DNC-1 完成。真实 DNS、CA 写入与两 VPS 验收由主代理统一执行。

## DNC-1 验证

2026-11-15，在已授权的 Linux Go 1.27.4 构建目录通过受影响模块的 `go test`、`go test -race`、`go vet`、`staticcheck`、`gofmt` 和根模块 `go mod tidy -diff`。本地 `tools/repo_lint.py` 的 SPDX、依赖边界、秘密与版本规则通过。21 个顶层测试包含写结果丢失、歧义归属、取消、限频拒绝、最终提交失败、并发恢复、外部修改、撤权、未清理引用保留、非法持久状态和有界传播等情形。

依赖复用已锁定的 `golang.org/x/net v0.60.0`（IDNA）与现有 clock；仅把 x/net 声明改为直接依赖，没有增加版本。敏感权限/并发路径按 HANDOFF §11.4 自审；异常清理日志缺失记录指针的拒绝校验已修复并回归，当前阶段没有未处理的 P0/P1/P2。真实后端与宿主接线保留为后续阶段，不能把这些 fake 测试作为真实 DNS/CA 成功证据。
