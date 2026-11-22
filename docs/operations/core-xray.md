# Xray 驱动：期望配置、应用与恢复

`core.xray` 使用 Core Intent v1 和锁定的 Xray 26.11.9。保存配置只更新 desired revision，运行核心保持原配置；使用 `core.apply` 将指定版本变为运行状态，使用 `core.observe` 按需读取当前代次的原始累计统计。

## 操作

- `core.capabilities`：区分声明、已验证及不可用能力。原生预检、私有 UDS 和最小 StatsService 已有 X6 真实证据；真实客户端转发和 per-user mark 未验收时保持不可用。
- `core.validate`：只做指定 desired 的纯校验；不会揭示秘密、写文件或运行原生预检。
- `core.status`：独立返回驱动、核心进程、API、desired/running、摘要和统计 epoch。SDK SERVING 只表示驱动 RPC 可用，代理可用以 `proxy_available` 为准。
- `core.observe`：只读/invoke，可用 kind=inbound/user 和稳定 ids 过滤；不接受 pattern/reset，不运行后台采集。每个方向独立标记 present，缺失值不补零。
- `core.apply`：声明 job/write/medium/confirm，宿主按高敏能力将有效风险提高到 high，按默认策略等待真人审批；MFA 下限适用于 destructive（ADR-0004）。支持 PlanOperation。请求只含 `config_revision` 和可选 `expected_running_revision`，不包含原生 JSON 或秘密。

```json
{
  "config_revision": "7",
  "expected_running_revision": "3"
}
```

省略 expected_running_revision 表示由计划或当前读取提供前置；显式空字符串表示“当前没有运行提交”。Plan 附带 `running/current` 前置，执行时在副作用前复核。版本必须是规范十进制字符串；未知、重复、null 或原生配置字段被拒绝。

## 状态与预演

UNCONFIGURED 表示没有 desired 或运行提交；PENDING_APPLY 表示期望与运行不同；APPLYING 表示事务正在切换；RUNNING 要求已提交配置与进程摘要一致且私有 API 健康。STOPPED、DEGRADED 和 FAILED 分别表示受控停止、API 不可用或核心/恢复故障。历史 last_error 不遮掉健康旧核心的 PENDING_APPLY。

Plan 只读取当前期望与私有提交元数据，显示监听、端口、用户增删、启停、条件重启和回滚能力。认证仅显示 changed/unchanged，不暴露 UUID、密钥、公钥、short_id 值或引用。原生预检及完整健康确认只在 Apply 执行。

## 应用与失败处理

每实例串行执行，所有阶段检查取消。受控 reveal 后生成确定性原生配置，候选在 operation/attempt 私有目录预检，随后安装不可变 generation。先确认旧进程已回收，再启动候选；健康后原子提交一个 state.json 中的 current/previous，再 CAS 更新本实例 Host KV 并报告 config/runtime 变化。

同一版本、摘要与实际健康状态一致时重放不会重启。新 desired 的原生配置字节相同时，只推进记录，保留 PID 与 epoch。enabled=false 仍完整校验和预检，之后提交 STOPPED，不会启动核心。

文件替换、CAS、报告、健康或取消失败进入有界补偿：先恢复旧指针，再恢复旧核心、复核健康并提交新 epoch。CAS 响应可能丢失时先读取实际值，只补偿仍属于本事务的记录。无法确认旧进程停止时不启动第二进程；无法恢复一致状态返回 RECOVERY_FAILED，不能声称回滚成功。

候选工作文件必须清理。业务提交后的 generation GC 失败返回 `GENERATION_CLEANUP_PENDING` 警告，保留实际已生效配置；后续幂等 Apply 或实例激活重新处理。不能用警告隐藏残留或把它当作已完成清理。

## 生命周期与私有存储

runtime/work 为私有目录，配置和状态文件为 0600。generation 以原生配置 SHA-256 命名，已存在文件不会覆盖；current/previous 在同一个状态文件原子提交。恢复逐一核对目录、文件、权限、版本及摘要，损坏或不兼容快照失败关闭，绝不从 work 猜配置。

激活无 current 时不启动核心；有 current 时只读已提交快照，无需 operation 或新的 secret reveal。恢复入口清理经过 owner/attempt 校验的中断 work，只保留 current/previous 配置。SDK 背景取消先 SIGTERM，之后有界强杀与 Wait；请求结束不取消已提交进程。私有 API 只启用 StatsService，无额外 TCP 管理端口。

已提交核心意外退出使驱动返回规范非零原因，交给已有 systemd 故障域重启策略；候选退出交给事务回滚。状态读取使用事务观察序号，避免混用旧状态文件与新进程。

## 验证边界

X8 实现验证使用真实 SDK、私有文件、原生渲染与短时 Go 假核心／fake 宿主。覆盖逐步失败与取消、原子文件和 CAS 不确定结果、报告失败、停止不确定、恢复失败、每步磁盘崩溃快照、并发状态、幂等、受控停止及清理。它不替代 X10/X11 的正式包、真实 Xray/systemd、客户端连接和资源峰值验收。

## 流量与进程代次

Observe 通过当前进程持有的私有 StatsService 客户端读取固定业务前缀，RPC 有 deadline、消息和系列数量上限，永远 reset=false。返回稳定面板 id、kind、上下行字节、reset_epoch、collected_at 与 source=xray。

字节用规范十进制字符串表示，保留 int64 大数精度；真实零值是 "0"，缺失方向省略对应字节字段并将方向 present 标为 false，整个系列 present 只有两个方向均存在时才为 true。默认读取当前入站和全部运行用户；显式空 ids 选中零个系列，不从 desired 未运行的用户猜测当前计数。

查询开始捕获进程 slot、摘要和 epoch，查询结束复核；事务或进程换代期间返回 CORE_API_UNAVAILABLE，而不会把旧计数附到新 epoch。调用方只能比较同一 epoch；跨 epoch 重新建立基线，不做负差分、累计拼接或生命周期总量。API 错误不返回伪造零值。

X9 单元/SDK/fake 进程边界已覆盖查询途中换代、零值/缺失、最大 int64、输入注入和不可用 API。真实客户端流量增长及重启后的计数清零/epoch 仍随 X11 实测，未以 fake 值替代。
