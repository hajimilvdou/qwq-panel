# ADR-0015：插件 id 与发布者绑定

- 状态：Accepted（2026-11-09，审查任务卡 SDK-07）
- 关联：ADR-0014、ARCH §6.2、§10.2、§10.4；降级保护见任务卡 PLG-11

## 背景

`TrustedKey.Publisher` 只把密钥绑到发布者，不约束插件 id；更新流程也只检查 id 相同。管理员把第三方发布者 B 的公钥加入信任根后，B 签的 `id:"security.scan"` 包能当作内置插件的更新装上，接管其数据、KV 与已授能力。

## 决策

1. **密钥可签的插件范围**：`TrustedKey.PluginIDs`（精确 id，或 `acme.*` 形式的前缀）。`nil` 不限制，与现有 API 兼容；空列表什么都不允许。`VerifyAndParse` 不匹配时返回 `PLUGIN_NAMESPACE_MISMATCH`。
2. **信任根格式**：`--trust-dir` 下 `<name>.pem` 旁可放 `<name>.policy.json`：`{"publisher":"acme","plugin_ids":["acme.*"]}`。没有此文件即不限制；未知字段或格式错误使信任根不可用（fail closed）。
3. **更新时的发布者连续性**：新包 `publisher.id` 与当前版本不同则以 `VALIDATION_FAILED` + `PUBLISHER_CHANGED` 拒绝，除非请求带 `accept_publisher_change: true`。
4. **只接受真人**：`accept_publisher_change` 由 HTTP 层校验，非真人会话一律 `PERMISSION_DENIED`。AI 与服务账户不能替用户决定把插件交给另一发布者。

## 后果

- 未写 policy 的旧信任根行为不变，只多了更新时的发布者检查。要限制某密钥可签的范围，运维需显式写 sidecar。
- 回滚不做发布者检查：回滚目标是此前已接受、仍保留的版本。
- 与 PLG-11 的关系：两者都是 `Update` 中 id 校验之后、saga 开始之前的独立检查，互不依赖，顺序不影响结果。

## 未采用

- 把范围写进 PEM 头或单一的集中配置：sidecar 不改变现有 `.pem` 的解析，也便于逐密钥增删。
- 发布者变更时要求单独的审批流：真人会话的显式字段已经满足“显式决定”，审批流留给操作管线统一处理。
