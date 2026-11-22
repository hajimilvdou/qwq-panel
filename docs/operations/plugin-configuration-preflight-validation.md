# 插件配置保存前的消费校验

日期：2026-11-18。范围：秘密内存投影、Controller完整候选/绑定校验、HTTP提取前守卫及实际保存适配器再次校验。

## 最终行为

配置请求携带网关确认的真实Actor，公共JSON不接受Actor。HTTP在ExtractSecrets之前调用ValidateConfig；cmd/qwq实际ApplyConfig入口再次调用同一Controller守卫。缺授权来源、取消、scope拒绝不会进入Updater写入。

核心候选先拒绝原始重复JSON字段及无效对象，再通过现有秘密schema walker将新字符串秘密投影为仅供结构校验的引用。已有引用身份保持，原配置不变；完整Core Intent v1/v2经过同一SDK严格解码与校验。投影不访问秘密库或DB，校验器返回后投影/临时字节缓冲清零。

Core配置的安装schema字节摘要必须匹配当前已安装manifest登记；实际配置revision必须等于请求前置条件。Hysteria2 profile的binding_ref、profile、node、SNI和用途由宿主解析完整候选后交给Authority.ValidateConsumerConfiguration；Test不接受请求升级。校验前后复核安装/配置快照与真实主体当前配置权限。

本阶段H2拒绝测试使用真实身份/Updater/私有Authority，并确认未预留或未装配后端时不产生secret/config/operation。成功的完整v1预检使用真实SQLite/身份/Updater与正式v1 schema。首个H2的Register→Reserve→配置→Bind真实正向闭环归生产装配后续任务，不能以这里的fixture或拒绝用例代替。

## 实际验证

用户保留完整历史账本，明确Root与唯一DNC各追加最多2轮Linux验证；Root两轮已使用，DNC额度独立。

| 检查 | 结果 |
|---|---|
| 追加第1轮native80780：secrets / controller / api全普通 | PASS，1.619s / 10.449s / 16.309s |
| 同轮cmd全普通 | 唯一失败为既有TestRegisterPublicRoutes仍预期85；bootstrap既有新增路由实际86。其他该轮结果保留 |
| 核验API/OpenAPI新增bootstrap路由并修断言、追加该必需路由检查 | 真实来源已确认；没有新增/删除生产路由 |
| 追加第2轮native84708：修正路由定向普通 | PASS，0.078s |
| 第2轮四包全race | PASS：secrets18.448s / controller73.676s / api81.660s / cmd17.163s |
| 四包vet / staticcheck、tidy-diff、repo_lint及cmd/qwq最终构建 | PASS |
| 11 Go SHA / Linux gofmt / 受检取回与token恢复 | PASS；194560 bytes，SHA `e9ec27e9ef929a7158b1871c29772b0e31859db302e539221a021fdf4030c3a7` |

最终log `.cache/sdd/gates/configuration-guard-extra2-20261118.log`，SHA `b7c999816d96927cc219b1cddc7f7678f7feaadf53f2f932487c5ff4d64bf677`，完整exit0。首轮log SHA `1ea9069ccfbcd44f2664e88740b46144eba82573bea51b9340d06edc58fa5c5d`。未重跑已通过且未改的三包普通；没有活动Root native句柄。

完整失败记录保留：旧来源阶段至少22条已确认工具/门禁错误；配置范围为错路径检索、22886 RED、api_test.go不存在检索、80780旧路由断言共4条。原3/5门禁子集不能作为完整历史计数。独立DNC原10与恢复后检索错误、bootstrap/GitHub旧额度均不调拨或清零。

## 敏感路径复核与继续范围

P0/P1：本次候选解析/真实主体/绑定拒绝路径没有未处理发现；已验证重复JSON、秘密错误形状、scope/来源/配置与schema换代、取消、HTTP拒绝先于秘密提取、直接适配器拒绝先于Updater。

P2后续工作：当前保存仍是既有直接PUT/提取后调用Updater的分段生命周期，不宣称跨secret提取/拒绝candidate/后端Apply的原子回滚，也不宣称完整统一host.plugins.config operation完成。动态秘密schema、稳定带密钥指纹、审批/API/AI/CLI/生成契约/UI，以及并发撤权/换代后的已提取秘密收尾须在统一配置执行链中补齐。原签名包资料和已拒绝candidate的诊断数据不在本阶段无依据删除。

全项目目标继续active：真实DNC生产装配、首次H2正向闭环、材料部署与续期、三协议原生驱动、IP-1–IP-6/RULE-1–RULE-5、其他规划和双VPS验收继续。
