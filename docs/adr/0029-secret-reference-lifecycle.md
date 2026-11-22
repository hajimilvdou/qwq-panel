# ADR-0029：秘密引用与资源生命周期

状态：已采纳；关联桌面审查 P1-CORE-04、P1-CORE-06。2026-11-18 两轮有界验证后通过，原失败完整保留。

## 问题与决定

计划执行会让同一个秘密同时被 plan 与 operation 使用；配置历史也会复用同一引用。只按插件 owner 或过期 plan 批量删除，会破坏仍在运行的操作与保留配置。保留 X3 的 `plugins/<id>` + 精确 purpose，不为清理改变插件秘密归属或扩大 Reveal 权限。

新增内部 `secret_references` 索引，记录 credential、plan、operation 与 config 对密文的引用。写入、删除以及最后引用消失后的密文删除，由同一 SQLite 写事务中的触发器完成；配置历史和已执行计划共享引用得到保留。插件 `purge_data` 明确删除该插件 owner 的全部秘密；默认卸载保留配置及其秘密。

迁移 0018 同时加入原施工方案预留的 `prev_token_sha256` 列，保持 0018/0019/0020 顺序。这里只交付该列的兼容 schema；双槽认证、升级提交清槽与回滚接线仍属于 P0-RT-01/P1-RT-01，不能据此宣称完成。0027、0028 仍留给地址族/中国分流与外部 CLI。

TOTP 新秘密以 `users/<user_id>` 存储，和待确认凭据在同一事务内提交。读取必须匹配用户、purpose 与当前凭据成员；旧 `system` owner 仅对该用户已经持有的 `identity.totp` 凭据兼容，不增加通用解密旁路。确认采用原凭据原地提升，避免删除待确认引用后提前回收密文。重绑、禁用、删用户、管理员恢复与过期待确认清理均复用引用生命周期。

参数/配置提取后，失败补偿只清理本次 `Extracted` 新建引用，且再核对引用索引；后端已提交快照后返回错误的场景不会误删已持久化秘密。已有配置引用不在本次新增清理集合内。

公开 Plan、ApprovalFacts、PlannedChange 与 API DTO 共用递归引用脱敏；原 Args 仍用于存储和执行。畸形引用、非法 JSON 与超深文档关闭输出，保留普通 JSON 数字精度。插件作者复制到预览 before/after 的引用也会被擦除。

公共 args 保持 OpenAPI 的 object 形态：整个参数对象敏感或损坏时使用 `{"$redacted":true}`，字段级秘密仍用 `[REDACTED]`。这只影响公开表示；不能拿公开标记替代私有执行参数。无引用的幂等正文保持原字节，旧带引用正文在回放时关闭泄露。

## 升级、资源与调用链

- 迁移回填现存合法引用，再清理已无引用的已知 credential/config/operation 用途；其他 purpose 与主指纹密钥保留。历史 `system` TOTP 只由真实凭据建立引用。无法解析旧配置 JSON 时整次迁移回滚，不把无法检查视为没有引用。迁移保持原 nonce、AAD、密文、ID 与 key_id，不重新加密存量数据。
- 空闲不增加 goroutine、FD、定时器或缓存；只为真实引用增加索引行。正常清理按秘密索引检查最后引用，不每次扫描全部 JSON 历史。
- 首次迁移扫描已有受限 JSON 文档并回填索引；失败整次回滚。请求路径仍使用原有 schema walker、单写事务与 AES-GCM。无新依赖、插件 ABI 或公开请求字段。
- SecretSealer 是宿主内部 seam，改为调用者事务及当前凭据归属；Controller、local CLI 都使用同一个 Store。测试使用真实 Store 验证事务与删除行为，保留密码/审计 fake。
- 所有批量删除必须经过已有资源删除路径；每次已公开资源变化的事件规则不变。待确认 TOTP 的内部维护仍不发布用户修改事件。

## 验证要求

覆盖公开计划/审批/agent DTO、原计划执行、共享配置/计划引用、事务回滚、旧库回填、TOTP 重绑/禁用/删除/恢复/过期、失败配置保存与 purge_data。普通、race、vet/staticcheck、仓库 lint 和 Controller 构建在 Linux；格式取回使用现有 SHA/成员/类型/token 守卫，随后独立 P0/P1/P2 复核。

验证证据：`.cache/sdd/reports/ROOT-secret-lifecycle-validation-20261118.md`。第一轮根模块普通发现两处旧安全夹具冲突；精确修正并保护 public args object 形态后，第二轮五包普通、十包 race/vet/staticcheck、lint、Controller build通过。其余根模块普通结果保留。全部源 SHA、格式归档 SHA/精确成员/token 守卫通过。完整项目、全仓十八门禁、1C1G峰值及双VPS/各端客户端边界验收仍未完成。
