# 代理准备功能：域名与 TLS 证书

- 关联：[首期代理设计](proxy-first-release.md)。状态：Accepted（用户 2026-11-14 确认），准备功能属于首期交付，不能在协议上线后补。
- 复用证据：`internal/tlsmgr/{tlsmgr,acme,selfsigned}.go` 已有管理监听器的自签名、ACME 缓存、证书解析、原子替换、到期状态与维护逻辑；`golang.org/x/crypto/acme` 已在依赖中。
- 当前缺口：没有通用域名/DNS 资源管理、DNS-01 适配、代理证书资源与绑定；现有 `autocert` 按 HTTPS 握手续期，不能据此保证仅 UDP 的 Hysteria2 会续期；HTTP-01 的 Handler 也尚未挂接监听器。

## 1. 业务与宿主边界

- 域名/DNS 模块管理提供商、zone、域名、记录、解析检查和影响面。
- 证书模块管理申请/导入/续期、证书资源、generation、绑定、告警和安全移除。
- 两个业务模块通过插件 operation/UI 暴露功能；业务状态用现有插件 config/KV/secret，不塞进宿主核心表。
- 宿主提供窄接口：固定提供商的 DNS 操作、受限 ACME 原语、证书校验与授权 materialize。复用现有 tlsmgr 的密码学/私有缓存/原子替换方法，拆出可复用部分而不复制完整 Manager。
- 能力服务独立版本化，不增加 Platform ABI v1 字段；不提供通用 HTTP、任意路径或任意证书 owner 的 reveal。
- 核心只收到 `certificate_ref` 与宿主确认的消费绑定；它不能传本地路径或揭示证书管理模块的 secret。X3 的 owner/purpose 绑定保持严格。

## 2. 域名与 DNS 管理

首期适配 Cloudflare DNS 和阿里云 DNS；提供商是可替换接口。只支持已授权 zone 内的 A/AAAA/CNAME/TXT 记录，禁止任意域名、API 主机或请求模板。

面板流程：添加提供商 → 以最小权限凭据读取可用 zone → 绑定已有域名 → 选择节点与 A/AAAA → 预演差异 → 确认写入 → 按权威 DNS 与递归 DNS 检查传播 → 关联 profile/证书。

- 不承担域名购买与注册商转移；用户把已有域名接入后，所需 DNS 与证书准备可在面板内完成。
- 凭据是 writeOnly/x-secret，保存后脱敏；替换/撤销时显示受影响的域名、证书续期和 profile。
- 每个写 operation 带 expected_revision；采用提供商的条件变更/记录 ID 与写后复核，不覆盖不属于该操作的记录。
- DNS-01 只创建该次 challenge 的 TXT，保留同名既有 TXT；记录 owner/attempt，成功、失败和取消均仅清理自己的记录。
- Cloudflare 普通 HTTP 代理不能当作 Hysteria2 UDP 转发；面板要求对应 A/AAAA 为 DNS only，并给出修复操作。
- 解析不一致、AAAA 指向错误节点、CAA 阻止签发、凭据失效、超时与提供商限频分别给稳定错误和重试建议。
- 重试只用于查询和具有确定幂等边界的 DNS 变更；有可能已经执行的写入先重读对账，不能直接重发。

数据最少包含：provider id/类型/secret ref/授权 zone，domain id/名称/zone/节点绑定，record id/类型/名称/值/TTL/提供商记录 ID/revision，challenge owner/attempt/记录 ID/到期时间；公开视图不显示 secret ref。

## 3. 证书资源与申请

首期支持 ACME DNS-01 自动申请、已有证书导入、受控自签名测试证书。HTTP-01/TLS-ALPN-01 仅在存在明确的 challenge 监听路由且不抢占现有服务时开放；不要求用户停宝塔或让 Hysteria2 占用 TCP 443。

- 默认公开 CA 为 Let's Encrypt；提供 ACME staging 供实验。CA 与提供商端点来自宿主受控配置，前端不能注入任意 URL。
- 申请 job：校验域名/授权/CAA → 生成私钥和 CSR → DNS-01 TXT → 等待传播 → 验证/签发 → 校验链/SAN/用途/私钥匹配/时间 → 持久 generation → 清理 TXT → 发事件。
- 私钥只在受控后端生成并持有；导入私钥经 secret 提取，不进入配置历史、operation 明文、日志、审计或事件。
- 每份证书有稳定 id、SAN、issuer、fingerprint、not_before/not_after、generation、revision、消费者与续期策略；公开证书链和私钥是不同可见性。
- 导入拒绝无效 PEM、私钥不匹配、域名不匹配、已过期/尚未生效和不支持用途。普通生产 Hysteria2 不自动打开 insecure。
- VLESS REALITY 和 simple-obfs 不强制申请不需要的证书；Hysteria2 必须绑定有效证书。面板 HTTPS 可选择授权证书，修改管理监听器绑定仍走既有高敏可达性流程。

## 4. 消费绑定与安全落地

绑定最少含 certificate id、允许的 plugin/profile/node、SAN、purpose、generation、policy revision；由宿主创建和校验，不相信插件自报路径或 owner。

- `materialize` 仅在允许的运行 operation 中把指定 generation 写入该消费者私有目录；固定相对路径、0600、fsync/rename/目录 fsync、属主与 symlink 校验。
- 管理模块持有证书 secret；消费者获得受限运行快照，不能获得通用跨 owner reveal。
- 证书与 Xray 配置 generation 一起进入 current/previous 引用集合；回滚固定到旧绑定 generation，不跟随“最新证书”改变旧快照。
- 消费者停止/卸载时移除该消费者 materialize 文件；共享证书仍被其他消费者引用时保留证书资源。
- 删除证书、域名、DNS 凭据前检查依赖；拒绝断开正在使用的绑定。解除绑定需明确预演和确认。
- X2 已记录 `/var/lib/qwq` 0700 父目录无法由动态 UID 遍历的问题。真实 materialize/X10 前必须以专用可遍历插件根及受控 StateDirectory 方案解决并更新 ADR-0012/0022；不能用放宽整个宿主数据树权限来掩盖它。

## 5. 自动续期与权限

采用低频、有界任务调度，按有效期提前续期并加入抖动；UDP-only 服务不依赖 HTTPS 握手触发。

- 初次启用自动续期时生成明确的资源范围策略：同 certificate、SAN 集合、provider、zone、CA 与消费者绑定；用户确认该范围。
- 每次续期以受控 service actor 创建可审计 operation，验证策略仍有效。只续现有证书，不能借此添加域名、替换提供商或扩大节点范围。
- DNS API 凭据和 ACME 账户密钥由受限宿主后端代用；插件和后台任务不自行调用通用 RevealSecret。
- 新续期 capability 是针对既定资源的窄权限；新增签发/改 SAN/改管理面绑定仍走各自审批与风险流程，不降低现有 system.tls 或 secret.reveal 风险下限。
- 权限/策略撤销、owner 删除、提供商变更立即阻止后续自动任务并告警。没有有效授权时不静默签发。
- 失败按 CA Retry-After 和有界退避安排重试，保留当前有效证书；逐级提示到期剩余时间与最后一次失败。到期不能虚报 ready，也不自动切到 insecure。
- 续期成功先保存新 generation；消费部署失败继续旧 generation，并单独报告“签发成功、部署失败”，可在面板重试部署或回滚。

## 6. operation 与页面

域名页面：provider/zone/domain/records/解析状态/关联项；证书页面：申请/导入/链与到期/续期策略/消费者/历史 generation；协议创建页直接链接缺失准备项。

| 操作组 | 必需行为 |
|---|---|
| 域名绑定、DNS 记录增删改、凭据替换 | expected_revision、受控 zone、差异预演、审批、写后复核、resource.changed |
| DNS 与域名检查 | read/invoke，无写入或凭据泄漏，显示解析来源与采样时间 |
| 证书签发/导入/续期 | 有界 job、幂等/attempt、取消清理、阶段进度、证书和 generation revision |
| 证书绑定/部署/回滚 | 明确消费者与影响面、前置条件、旧 generation 保留、真实健康检查 |
| 自动续期设置/撤销 | 展示授权范围与风险、审计 policy revision、撤销即时生效 |
| 敏感材料显示/导出 | 按人类会话/权限单独授权，默认脱敏，下载只含用户选定内容；不进入事件与日志 |

## 7. 验收

- fake DNS provider、fake ACME server、fake clock 测正常/限频/断网/取消/部分成功/竞态/撤权；验证没有漏删本次 TXT 或误删他人记录。
- 测证书链/私钥/SAN/到期校验，非法路径、symlink、其他 owner/节点/plugin/profile 的 materialize 全拒绝。
- 测无 HTTPS 握手情况下自动续期仍触发；策略扩大或撤销后无法执行；签发成功但部署失败保留旧运行代。
- 两 VPS 用专用子域和 ACME staging 做面板完整准备 → Hysteria2 TLS 连接 → 换代 → 回滚 → 清理。
- 所有写入可追溯到 operation，公开输出无私钥、DNS token、ACME 账户密钥、PSK、UUID 或完整秘密引用。
