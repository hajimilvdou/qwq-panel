# ADR-0026：服务账号的精确资源作用域

- 日期：2026-11-17。
- 状态：Accepted（按用户已批准的自动续期及最小权限要求落实）。
- 关联：ADR-0004、ADR-0025。

## 问题

`authz.authorizeService` 目前只检查服务账号角色与禁用状态，没有检查动作、节点或资源目标。为证书自动续期分配operator角色会同时取得其他插件写权限；模块内部的证书策略不能限制整个宿主授权入口。现有`CreateServiceAccount`要求真实人类会话，取消补偿的ConfirmationActor明确不含SessionID，不能用它创建新账号。

## 决策

1. 服务账号增加可选通用`scope`：精确`actions`、`node_ids`、`subjects`及`expires_at`。四项均必填且有界，不接受通配、空列表、目录穿越或无限期；数据只描述权限，不保存证书/SAN/DNS/CA业务状态。
2. `scope=NULL`保留旧账号行为；非空JSON必须严格解析并完整校验，错误或过期时拒绝，不能降级为旧角色授权。新续期身份必须提供scope。
3. 授权取账号角色、scope和创建者当前RBAC的交集；账号/创建者禁用、创建者撤权、到期或目标缺失均拒绝。每次授权重新读取，scope不授予human-only权限。
4. `authz.Resource`增加内部`Subject`字段。operations适配器传真实`Target.Subject`；服务账号所属原生AI会话沿同一检查链，不能经会话扩大权限。scope要求的维度不能因空action/node/subject而跳过。
5. 创建沿既有真实人类会话和同步HostHandler路径，账号、operation、审计和resource.changed同事务提交。续期bootstrap只返回账号ID，令牌不进入operation结果；证书/SAN/provider/CA等精确业务范围继续由私有续期策略逐步复核。
6. 当前主线迁移最大0015，迁移加载器要求连续编号，新增0016_service_account_scopes.sql。旧停止p6-cap克隆中0016_private_exports.sql保持原样且不恢复；该历史未合入文件不能直接合入新的迁移序列，未来若获准恢复需重新规划编号。

## 边界与代价

scope只收紧角色，不替代插件capability、当前operation、私有业务策略或新的人类登录。既有未设置scope的账号保持兼容；读取已撤销/过期的scope不会产生默认权限。授权多一次创建者RBAC查询，换取即时撤权。字段和方法全部在宿主内部，冻结Platform ABI和SDK模块依赖不变。

## 验收

真实SQLite创建、重新加载和Bearer认证后，只有完整匹配的动作/节点/subject可写；缺失或不同维度拒绝。服务账号所属AI会话保持同一上限。到期、创建者降为viewer/禁用、账号禁用/删除立即拒绝；未知字段、重复键、非法JSON/null/空作用域不得退化。旧账号生命周期与权限矩阵、受影响race/vet/staticcheck及合入门禁通过。bootstrap和消费者接口另在ADR-0025实施阶段接线，不能用本授权模型声明完整续期已上线。
