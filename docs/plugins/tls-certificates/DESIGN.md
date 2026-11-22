# 证书模块实施设计

- 依据：Accepted 的 [首期准备设计](../../design/proxy-prerequisites.md)。独立业务插件为 `tls.certificates`。
- DNC-2A：材料校验、真实加密材料库、generation、绑定、回滚和引用保护。
- DNC-2B：精确续期授权账本与有界 service actor 核心；真实 DNS/CA、capability RPC、插件 operation/UI、宿主注册点和两 VPS 验收仍需后续闭环。

## 密码学复用

`internal/tlsmgr/material.go` 复用既有管理监听器的证书/私钥解析和指纹算法，`selfsigned.go` 保留原函数签名与管理证书有效期。受控测试证书复用相同生成模板，固定到当前时间后一天到期。

新导入校验严格检查首个 PEM 块，拒绝前缀垃圾、损坏块、尾随垃圾、未知块和重复证书。校验私钥匹配、支持算法强度、服务端用途、信任链、exact SAN 和生效/到期时间。测试证书与 staging 信任必须显式选择，普通生产消费者仅接受公开可信 TLS 服务端证书；没有自动 insecure 行为。

## 真实加密材料库

`certificates.Vault` 复用现有 secrets AES-GCM、owner/purpose AAD、单写事务和清零。owner 由宿主根据固定模块、资源 owner 和 certificate id 生成；purpose 固定到该 certificate 下的 attempt。材料定位符仅进入私有状态，公开证书 DTO 不含 secret ref、私钥或路径。

`secrets.FindOwned/EnsureOwned` 是宿主私有原语。查询最多两行，已有多条 owner/purpose 记录明确拒绝歧义；同事务中先查询再保存。同名称同内容返回原引用，不同内容明确冲突。内容以固定长度 SHA-256 摘要作常量时间比较，复用原 decrypt/AAD 与清零，不另建解密旁路。

导入私钥由 `OwnedImportKeys` 先验证当前派发 operation 的引用集合，再按固定 `plugins/tls.certificates` / `plugin.operation` 揭示。该权限绑定仍需宿主注册点接入真实 operation resolver；未接线时材料库 constructor/接口不得伪造授权。

## 资源与 generation

业务状态通过带 CAS 的 repository 保存，schema 不进入宿主业务表。证书有稳定 id、不可静默扩大的 SAN/用途、公开元数据、按序 generation 和受控材料引用。需要更改 SAN/用途时创建新证书资源并重新绑定；自动续期只能保留原 exact 范围。

申请、导入和测试生成均先保存 pending，再使用按 attempt 幂等的材料服务。签发响应丢失不重发 CA 订单；当前已授权 operation 可以读取保存的原 attempt 对账，不复用已结束的派发权限。材料引用先保存，校验后再保存 generation；最后保存失败不返回尚未持久化的 ready。

## 绑定与部署

宿主确认 plugin/profile/node/SNI/purpose/generation/policy revision。绑定请求没有任意路径或 owner。消费者实际运行代与最新签发代分开保存；只有宿主返回目标代及真实健康确认后更新运行代。

部署失败确认回滚时保留旧运行代，报告 issued_deployment_failed；结果不确定时保留 pending、取消消费者 verified 标记，并只允许对账。回滚固定到保存的 previous generation，不跟随当前最新证书。过期、错误域名或测试信任不能绕过校验。

## 安全清理

当前/previous/待部署引用均保护证书材料。业务绑定之外，还必须查询宿主真实快照引用。删除锁覆盖该查询、材料清理与状态提交，宿主的新增消费引用必须参加同一锁，防止删除竞态。

删除代、解除绑定和删除整份证书均先写 pending，部分完成可由新的已授权 operation 对账。解除绑定由宿主确认消费者停止或已脱离资源，只清理其私有副本。整份证书删除在 pending 期间不报告 ready。共享证书仍有任何引用时拒绝删除。

## 精确续期核心与宿主接线

续期核心以宿主私有授权账本保存用户确认的 certificate/SAN/provider/zone/CA/consumer 集合，不能使用插件可任意改写的 KV 作为授权事实。Run 采用低频 clock、有界任务数/超时/最多五次失败预算；每次创建新的可审计 operation，每个关键阶段重读 policy revision 与资源授权。撤销先 CAS 保存新 revision，再取消本进程任务，后续原语失去授权。

签发前持久化原 attempt、请求 hash 和资源 revision；轮次计数单调递增。租约过期或重启只恢复该原意图、已保存材料或原签发收据，不将资源最新 generation 冒充该次结果。generation 发布与续期阶段提交之间崩溃也不会重发订单。明确拒绝的 CA Retry-After 持久化进收据，重放保留等待时间；不确定写入不创建替代订单。

目标 generation 在部署前 CAS 保存，TXT 清理确认后才部署。部分部署只重试未就绪消费者，旧运行代、回滚代与稳定 binding ID 保留。签发后清理失败、部署失败、审计失败、重试耗尽和证书到期分别报告。共享账本中的活动租约共同计入任务容量，不能由多个服务实例各自叠加 MaxJobs。插件 background 不能自行取 secret 或凭无 operation 的定时器签发。

新 capability v1 不修改冻结 Platform ABI。当前 Authority/Bindings/ImportAuthorizations/RenewalConfirmations/RenewalOperations 测试采用明确的 fake 注入；真实加密 Vault、续期核心与已有 TLS 管理器回归已经执行，但不能据此声称真实 CA 签发、宿主 service operation 接线、运行目录 materialize、Hysteria2 TLS 或两 VPS 验收完成。

## DNC-3E3：真实宿主证书授权

`hostauth.CertificateContext` 从原已接受的证书 operation 参数建立私有范围，固定控制面 owner/node、certificate、attempt、exact SAN/用途、受控 CA 及 provider/zone 版本。登记的创建者是审计事实；同作用域合法操作者可以使用共享资源，原证书 ID 上的 SAN 和用途不能静默扩大或替换。登记复用真实加密 KV 的严格文档校验、共享预算及 CAS。

`CertificateAuthorizer` 每步重查原派发、当前 RBAC/limits、私有登记与实际凭据。申请、导入、测试和删除请求由宿主直接从已接受意图构造，并复制返回的 SAN，RPC 不能用替代 caller、CA、scope、attempt 或 generation 增权。删除 generation 的执行和恢复把精确代传入授权，在材料清理前再次校验，撤权时保留 pending 对账证据。

导入授权已经通过真实 `ExtractSecrets`、operation、身份与 Vault 接口执行；读取只能使用原已接受的单个引用，固定 `plugins/tls.certificates` / `plugin.operation`，读取完成后再次检查当前权限再返回 PEM。CA 条款只接受原申请选择的受控 CA 和官方文档地址，并保存原发起 operation 的私有证据；发起人不冒充审批人，也不能凭该证据创建服务账号。

本阶段验证使用真实 Identity/RBAC/SQLite/AES-GCM/operations，以及明确的 Cloudflare 协议和 CA 证书夹具；没有访问真实 DNS/CA。consumer、续期 service operation、取消后的精确 TXT permit、任务和生产 capability 接线仍需后续阶段。相关 source 缺失时拒绝执行，不用插件 KV 或粗 service 角色填补授权事实。

## 原请求与逐 TXT 清理授权

原 CA 请求匹配复用实际加密订单与 CSR 校验；正常提交、恢复和清理逐一核对 certificate、issue/DNS attempt、SAN 的 TXT 名称和值及原快照版本。DNS 的私有自有记录证明只由同一个 Manager 从受检日志生成，固定实际记录 ID 和完整指纹；未知创建响应保留证据，不认领其他同名同值记录。

`CertificateCleanupContexts.Source` 读取订单前即打开原 executor 的硬窗口；Source-only 不能访问提供商或取凭据，逐记录 context 才可以读取对账并删除原记录。每次仍复查当前角色、服务/委托限制、精确 provider/zone 和凭据状态；停止原宿主 context、executor 结束或窗口耗尽后拒绝。错误私有 context 和私有凭据失败均不退回正常 DNS 路径。

取消后的补偿与新的超时预算分开处理：补偿可以脱离 cancellation，查询和持久化仍继承更早 deadline，过期输入不会获得新预算。订单 JSON 解码不能改写调用方的 SAN 切片。此阶段真实身份与私有持久后端的回归已执行；真实续期身份、消费者 source、任务/RPC/插件页面和两 VPS staging 仍待后续接线。
