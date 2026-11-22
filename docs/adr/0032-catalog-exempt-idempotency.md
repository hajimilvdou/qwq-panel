# ADR-0032：目录豁免写路由的事务幂等

状态：已接受，2026-11-20；对应 P1-CORE-05 的目录写入范围。

委托创建、更新、删除和首次密码链接发行原先在内存先 lookup、后写数据库、最后 store。同键并发能创建两份委托；宿主重启后丢键并再次发放一次性凭据。过期 cache 的 order 还可能淘汰重插的新键，委托 token 也会在进程缓存保留 24 小时。

四个入口复用 operations 的 idempotency_keys、原 principal/method/path/key 范围、请求指纹、24 小时 TTL 和每主体配额。ClaimIdempotencyTx、LookupIdempotencyTx、CompleteIdempotencyTx 抽取原存储逻辑；普通 Run/ExecutePlan/Decide 继续通过原外围事务取得和完成声明，原 operation 绑定与失败释放规则保持。精确键过期后可在本次事务重用，其他新鲜键不受清理影响。

目录写入共用 catalogWrite：同一 BEGIN IMMEDIATE 内先重查当前人类角色，再取得键，执行原领域写入和审计，序列化安全回放，最后提交。业务错误、序列化或回放写入失败均回滚整笔事务；请求取消不留下半次发行。重复请求在 SQLite 写连接串行化后读取同一已提交结果，不持有长期进程缓存或新 goroutine。

委托更新和删除还在回放前复用领域原有 owner/admin 规则。更新 DTO 的 owner_id 来源于首次事务的宿主行；删除则在同一事务保存原 owner_id 为私有回放事实，204 始终不输出该正文。管理员降为 operator 后仍有全局写权限，但不能回放他人委托；本人的合法删除在行已不存在时仍返回原 204。缺失或损坏的归属事实拒绝，不按角色另建键，也不信客户端提供 owner。普通领域写入与回放共享同一对象规则，当前角色通过调用方事务读取。

token 和 enrollment_token 仅保留在首个 HTTP 响应，通过既有 withoutMember 在落库前移除。首次密码链接在消耗 MFA 前以同事务角色核验读取既有安全回放；需要新发行时保留原 MFA 验证，再进入原子写入并重验权限。重启后仍能读取同一安全回放；HTTP 状态、expected_revision、本人范围及令牌仅展示一次的合同保持。

插件生命周期的五个 replayCache 调用点涉及外部进程，不能放进本地数据库事务。它们仍属于 P1-CORE-05 后续完整范围，必须绑定真实持久 operation/saga 与执行中状态；本 ADR 的目录修复不代表整个 P1-CORE-05 已完成。

回归先在旧代码复现同键双创建、真实 Controller 重启后重新发放、回放事务失败未回滚领域/审计/事件，以及管理员降权后的他人对象回放。修复后验证原授权/角色变更、MFA、幂等指纹、只展示一次、本人删除回放及 operations 的原绑定、过期和失败恢复。Linux 45679 完整 exit 0：七包普通/race/vet/staticcheck、仓库 lint 和宿主构建通过；10Go 格式的 SHA、成员、类型、父路径及 token 核验后恢复，Root 与唯一工程代理独立复核未见本范围新增 P0/P1/P2 阻断。
