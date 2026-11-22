# 真实会话续期账号入口验证：2026-11-18

真实浏览器会话通过 `POST /api/v1/service-accounts/renewal-bootstrap` 提交私有策略 ID 与 revision，等待高风险审批。执行时再次从当前事务核验会话和角色，并从宿主装配的只读策略源取得固定范围；只创建指定证书、节点、动作和期限的 operator 账号。账号、操作结果、成功审计和资源事件共同提交或回滚，公共结果只有 service ID。

原生操作目录与 HTTP 使用同一 `host.service_accounts.renewal_bootstrap`。共享网关拒绝重复 JSON 字段，包括转义后等价字段，并保留原字节、深度、数字和 DTO 规则。完整私有 scope 固定属于 tls.certificates；确定性账号名绑定完整范围、实际节点和当前真人 ID，匹配账号可复用，权限、创建者或状态不符则拒绝。

## 实际验证

- 原5次失败完整保留：既有接口 RED、新动作目录 RED、本机 snapshot 启动失败和两次业务验证失败。用户明确追加最多2次后，只使用第1次即成功，第2次未使用。
- Linux 构建机原生5319完整exit0：三组字段去重顶层（包含转义、数组、JSON Pointer、合法独立object、原语值、语法/深度/大小）与原失败HTTP认证/重复字段负例全部PASS；gateway全普通5.140s、operations全普通9.495s。
- 敏感路径全包race：gateway15.446s、authz13.250s、identity55.290s、controller45.848s、api81.633s、operations101.297s，全部PASS。七包vet/staticcheck、根模块tidy-diff、仓库四项lint、OpenAPI100条规则和最终cmd构建全部PASS。
- 源码未变的早先普通结果沿用：authz1.068s、identity9.038s、catalog0.051s；controller真实创建/同事务会话撤销/生命周期proof/独立scope/回滚与同名账号冲突全PASS，HTTP正常审批、精确scope、只返回ID、幂等重放/冲突/复用和缺后端无账号残留全PASS。
- 完整验证日志SHA256：`32bddc2ed7d7d4506637cb51bececaa0185328b958764da8d69976893cc90ae3`。18文件153600-byte最终格式归档SHA256：`7bc9f5e71131f2f4c3cf157fe75d0b9f5b3c4b23dc903c67442260b22b7f4e41`；原源码SHA、白名单/普通类型/重解析点和token全部核验后原位恢复，源码语义不变。
- Node22.23.5 Jod仅安装于构建机项目工具目录，官方校验和已核验。前端依赖沿已有lockfile安装98包；TypeScript在Linux生成并check通过，受检取回后原64路由保留，新增1。最终检查确认无生成漂移。

## 集成与边界

私有登记来源 `0d2a592` 摘取为 `f30b470`；真实派发任务生命周期来源 `087d281` 摘取为 `f6766dd`，5文件blob完全一致，联合检查包含完整operations回归/race。未重复X11/VPS、旧18项门禁或用尽的追加流量次数；没有安装Windows Go、全局包、改变ABI或暴露秘密。

根据HANDOFF §11.4自审，本接缝P0/P1/P2无未处理项。输入不再存在重复字段覆盖歧义；会话/同事务撤权、错误范围、缺后端、取消、证明结束和数据库回滚均封闭拒绝，所有异步路径有错误返回，未新增无界任务、缓存、核心业务表或任意路径能力。

验证中的只读策略源是显式fixture。真实DNC的Register/Prepare/Attach库已另有验证，但当前生产ConsumerSource、ReservationSource、配置保存钩子、后台能力任务/RPC和controller装配仍继续实施；这批入口通过不等于证书自动续期、材料部署或完整DNC交付。整个规划目标持续active。
