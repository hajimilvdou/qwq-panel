# ADR-0025：域名、DNS 与证书的受限宿主能力

- 状态：Accepted；业务范围依据用户确认的 [代理准备设计](../design/proxy-prerequisites.md)，实施共享边界于 2026-11-16 由主代理确认。
- 关联：ADR-0004、0007、0013、0019、0022；Platform ABI v1 的既有字段与 SDK Host 签名保持不变。

## 决策

域名与证书分别由 `domain.dns`、`tls.certificates` 插件提供 operation、schema 和 UI。宿主按固定的独立 capability v1 RPC 提供 Cloudflare/阿里云 DNS、ACME DNS-01、证书校验、授权绑定与私有落盘；沿用 Host 通道的 peer/token、实例授权、派发、审计和错误门，不开放通用 HTTP、文件路径或跨 owner 的 RevealSecret。

scope 的 provider/zone/credential revision、证书 owner、consumer 和 policy revision 由宿主从已授权 operation 与私有登记账本确认。请求只能传资源 ID、expected revision 和该动作的业务参数；不能提供 API URL、CA URL、材料 owner 或运行路径。业务资源复用插件 config/KV，授权事实存放在插件不可任意改写的宿主私有账本中。

资源 OwnerID 代表宿主登记的控制面/模块固定作用域，不永久绑定首次操作者。CreatedBy、确认人和实际 service actor 单独记录；同一节点和登记作用域内的合法操作者按当前 RBAC 管理共享资源，跨模块、节点或登记作用域仍拒绝。每次续期同时检查确认人的当前权限和真实服务账号，不能把模块资源 owner 当作操作者身份。

取消补偿 permit 仅由已确认的宿主运行上下文派生，私有、不可序列化、不能作为 RPC bearer。它绑定原 intent/actor/action/node/plugin/instance/subject/provider/zone、确认记录 ID 和完整指纹，只允许在硬 cleanup budget 内删除该次自有 TXT；不能申请其他材料或扩大写权限。每次仍重查当前 RBAC、服务账号/委托、limits、凭据和 policy；撤权或过期保留证据并报告清理失败。重启后旧 permit 无效，恢复必须使用新的真实授权 operation 对账原意图。

运行 proof 同时绑定原 `*operations.Service`、`*runningJob`、StartedAt 与 Attempt。普通派发 resolver 的 RUNNING/未取消规则保持严格；取消后的补偿使用独立窄接口。`runningJob.cleanupWindow` 是唯一额外私有字段，由现有 runMu 保护、保持零值构造。首次读取原 certificate/issue/DNS attempt 清理候选事实即开启不超过30秒的硬窗口，读取耗时计入；fresh snapshot、其他自有 TXT 或较长请求 TTL 都不能延长该窗口，到期后同 executor 永远不能重新开启。executor done、映射替换或新宿主实例立即使旧 proof 失效。runMu 只保护短暂映射/窗口核对，不跨数据库、权限或网络调用；这些步骤前后核对原指针及不可变意图。

ConfirmationActor 仅来自实际有效的 Approved Approval.DecidedBy；无审批时保持空值。该元数据显式不含 SessionID/MFA，不能冒充控制面会话或创建服务账号。TXT 归属必须来自原私有写入日志的实际 ID 和完整指纹；未知 DELETE 先查询原 ID 对账，不能重新发送删除或认领其他同名同值记录。生产 CleanupContexts 缺失时拒绝执行，不退回宽 scope cleanup。

在读取原 ACME journal 前，CleanupContexts.Source 按原已接受 certificate_id、issue attempt、exact scope/subject 开启上述窗口。只有该初始私有读取允许空 DNSAttemptID；它不能访问其他 certificate/policy、提供商凭据或 DNS 请求。逐 TXT 的 Context 和 CleanupLease 必须改用原 journal 与真实 OwnedChallenge 核验的非空 DNS attempt、record ID 和完整指纹，并复用最早窗口；读取耗尽窗口后不再允许 mint 或发送请求。

正常 DNS-01 提交与恢复同样从原私有 CA journal 匹配实际 Name、TXT、DNS round/attempt 和原快照版本；先授权原查询，再把读到的实际请求绑定到当前真实 operation。wildcard 与普通 SAN 只共享规范化 TXT 名称，不能互换不同 attempt。`dns.OwnedChallenge` 只由指定 Manager 的受检私有日志产生，未知 ID 不认领同名同值记录，序列化不携带任何可恢复证明。清理凭据的私有选路失败时拒绝执行，不回落普通凭据路径。

窄补偿可以脱离普通 cancellation，但不能丢弃传入的更早 deadline。查询、已确认创建的对账、删除对账、finish/unknown 和加密订单保存均复用有界预算传播；已过期输入立即拒绝，不重新加时。原订单解码先复制授权 SAN 切片，持久 JSON 不能通过复用调用方内存改写请求范围或影响后续比较。

原自有 TXT 查询和直接清理缺失私有 receipt 时返回 `OUTCOME_UNKNOWN`，不能把没有日志解释成没有外部写入或已经清理。只有明确 `Cleaned/Rejected` receipt 才能返回已完成事实；ACME 保留未确认 challenge。辅助 `WithChallenge` 回调后的补偿复用 `contextbudget.Detached`，取消后仍保留更早期限，到期后不发送查询、删除或持久化，也不扩大补偿授权。DNS 同实例串行门采用零值可用的私有容量 1 token，正常变更、恢复、原记录读取与清理等待均接受当前 context，acquire 前后检查取消；锁竞争耗时计入原硬窗口，不增加 goroutine 或延长 deadline。

`system.dns.manage`、`system.certificates.manage` 保持 high 风险下限。`certificates.renew_existing` 只接受初次确认的同 certificate/SAN/provider/zone/CA/consumer 集合，通过真实受控 service operation 执行；不授予通用 bearer、secret.reveal 或增加 SAN 的能力。管理监听器绑定继续原 system.tls 与可达性流程。服务账号的粗角色本身不等于续期授权，每步必须重读精确策略和撤权状态。

证书请求可能超过 Host unary 默认时间，采用有界宿主任务的提交/查询接口承载，后台任务保留并反复校验原派发 operation，受宿主生命周期、取消、硬超时、共享租约和任务上限约束。重启恢复原 attempt、CA order/CSR/材料与固定 generation，不生成未知订单的替代品。

固定 capability 路由只从实际 operation 读取候选 plugin/instance/action/完整target，再由原私有 executor proof 复核身份、策略和原意图；SQL行、RPC metadata或持久任务来源都不能创建运行许可。额外 `AuthorizeCurrent` 只检查当前私有Actor的宿主权限，拒绝System、普通/不同Authority上下文、取消与释放，不返回Actor/Args，也不提供另一proof。

独立证书任务最多8个worker及8个监视器，监视间隔有界为100ms至5s。每阶段切换、持久进度及监视重新授权；相同原operation/kind/certificate/attempt/revision去重。默认60次/min的AI委托在5s监视下最多1个任务，为业务请求保留一半稳态监视预算。任务进度单调、固定阶段、每秒最多一次持久进度写入，终态始终尝试保存；同步执行器panic转固定INTERNAL并收尾，不输出panic值。最终收据保存失败由Wait/Close明确报告，旧queued/running行在无实际worker时只返回outcome_unknown，不自动复活原权限或重发外部请求。

普通DNS恢复须实现窄 `RecoveryAuthorizations`，并比对当前原DNSArgs中的唯一attempt、provider和zone；缺少该来源拒绝恢复。Reconcile只查询实际提供商状态并保存原意图收据，不提供Manage或CA cleanup许可。证书DNS-01继续原私有CA来源和已确认自有TXT边界。

需要宿主派发上下文的只读能力显式声明 `effect=read`、`mode=job`，沿用现有持久 operation、幂等键、共享任务上限、当前权限、取消与 deadline；同样拒绝新的秘密材料。`read+invoke` 保持同步 200、无 operation 记录和原 widget 轮询。现有审批、父操作风险/权限继承和 MFA 规则不因只读 job 放宽，Platform ABI v1 与 SDK Host 保持不变。

消费只使用稳定 HostBinding.ID，生产由既有宿主 ID 生成器生成 `certbind_` 前缀和26字符后缀、受控 ASCII、不超过 128 字节。`hysteria2.tls.{binding_ref,server_name}` 由宿主确认到具体 plugin/profile/node/purpose/SNI/generation；materialize 不接受路径或 owner。固定相对文件写入消费者受控私有目录，0600、属主与 symlink 检查、fsync/rename/目录 fsync；current/previous/候选快照引用参与同一删除锁，旧配置回滚固定旧证书代。

初次配置先经真实高风险 `bindings.reserve` operation，由独立 `ConsumerReservationSource` 核验拟建消费者、真实安装能力、配置前置版本与授权Test事实，在现有加密authorizations KV的最多256条单ledger中用CAS预留稳定ID。预留仅描述证书/SAN与消费范围，不证明已有v2配置或材料ready，也不授予materialize；不能要求先存在BindingRef而阻断首个profile。

真实配置入口解析完整候选并调用 `ValidateConsumerConfiguration`，按当前Actor重查 `host.plugins:config`、固定 `host.plugins.config` action、实际node及 `plugins/<plugin>/config` subject，并核验精确profile/SNI/purpose与私有reserved/confirmed登记。合法普通Service仍经当前role/scope/creator交集，System不能旁路。reserved首次匹配预留时的原配置revision；confirmed后重读真实CurrentConsumer事实同Ref/Test/实际版本，允许正常配置更新，不重开已结束的原job。Origin保存明确私有字段，不使用Invocation脱敏JSON、不包含运行proof；它只供纯配置facts source标识原来源。真实绑定再从原Args固定generation/attempt，通过当次不可序列化context确认授权；部署健康与运行代继续由真实后端单独验收。

## 写入与恢复边界

DNS 先保存 CAS 意图、完整 zone revision 与原记录指纹，再发送一次变更。完整指纹纳入 API 元数据，保护 tags/comment/priority/status 等外部变化；业务内容对账不把提供商元数据版本当作用户要求的新内容。Cloudflare 以创建时的原子 comment 标记或已保存响应 ID 认领；阿里云没有原子归属标记时只依赖已保存 ID，丢失 ID 保留 unknown，同名同值 TXT 不作为所有权证据。

明确 4xx/限频拒绝保留稳定错误和 Retry-After；未知/矛盾响应、5xx、网络中断和响应丢失均先读对账，不自动重发写入。API 不提供条件写事务时，紧邻提交的目标复核仍有外部写入窗口，不能把本地 CAS 描述成提供商原子事务。成功、失败和取消只清理该次已确认的 TXT；无法确认或凭据已撤销时保留证据并告警。

## 官方接口依据与验收

- [Cloudflare create DNS record](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/)：固定 REST v4、原子 comment、proxied 与 TTL。
- [阿里云 AddDomainRecord](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-adddomainrecord)：固定 RPC 2015-01-09、RecordId 与 TTL；[官方签名实现](https://github.com/aliyun/alibaba-cloud-sdk-go/blob/master/sdk/auth/rpc_signature_composer.go) 确认 HMAC-SHA1 和 canonical percent encoding。该算法仅用于官方 RPC 签名，材料与资源摘要采用 SHA-256。
- `golang.org/x/crypto/acme` 已锁定在依赖中；显式限制其写重试，持久订单/CSR，并校验受控目录、链、exact SAN/用途、私钥与生效/到期时间。staging/test 信任必须显式选择。

构造依赖缺失时失败关闭，测试 fake 与真实接线分别记录。最终必须包含 provider 协议、授权/并发/取消/磁盘失败回归、独立 RPC/插件页面、真实 actor/materialize 和主代理统一的两 VPS staging 验收；阶段库或模拟 HTTP fixture 通过不能代替完整验收。独立证书能力 `BindingView` 仅追加只读字段 `previous_generation = 11` 以暴露已验证回滚代际，Platform ABI v1 保持不变。
