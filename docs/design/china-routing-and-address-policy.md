# 中国用户分流与双端地址选择

日期：2026-11-18。用户已确认：客户端默认国内直连、境外和未命中走代理，局域网和面板管理地址保留直连。流量进入VPS代理后，VPS对所有目标应用默认IPv4/IPv6策略，用户指定网站可以覆盖默认；两段策略独立。

## 已取回核验的开源参考

| 参考 | 本次取得的证据 | 采用范围 |
|---|---|---|
| [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) | repo metadata、LICENSE(MIT)、README；2026-11-18仍非archived | 首选域名分类原始来源。项目明确不决定哪些网站应代理，执行策略由面板按用户选择生成 |
| [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) | metadata、GPL-3.0文本、README；声明GitHub Actions北京时间每日6:30构建 | 参考domain/IP规则集、direct/proxy/private格式与更新流程；上游和可分发许可继续逐链核验 |
| [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) | metadata、GPL-3.0文本、README；提供dat/MRS及sing分支，CN分类有ChinaMax等上游覆盖 | 参考Mihomo/sing-box适配及中国应用/CDN分类；规则源、lite覆盖和上游许可不能混成统一已验证资料 |

SagerNet/sing-geosite本轮HTTP请求失败，未取得元数据/许可，暂不据此选型。前3成功资料不重复查询；用户批准的Linux第2批同范围只读核验尚未使用。

当前证据是源码说明与许可文本，不代表已拉取、编译或验收实际规则数据。主工作区 `.cache/sdd/research/routing-20261118-extra1.log`，SHA `de74f395f2da913b3d58c6f09653030496f67d715a54ac513e62fd7dd94faeca`。v2fly LICENSE SHA `b9d84a22870d3f21c91a4c6e410c9cc51d00902f5233ad0c84011479244bf7d2`；另外两库本次GPL文本 SHA `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`。

## 执行策略

1. 管理/局域网直连保障与用户业务覆盖规则先匹配。
2. 国内域名及明确中国大陆IP走直连，境外域名走代理，未命中走代理。中国应用的国内节点/CDN分类独立于仅按服务品牌的规则，不把同一共享IP全部归为某网站。
3. 域名分类和IP网段分类分别记录来源、版本和覆盖地址族。clash-rules README的中国大陆地址来源只明确IPv4；IPv6国内范围须独立核验和验收，不能把IPv4列表当双栈已覆盖。
4. DNS按最终直连/代理路径解析，保留目标身份、A/AAAA、缓存TTL和变化后的回退行为。实际锁定驱动字段先查证，禁止把示例中的最后直连规则或广告拦截直接当本产品默认。
5. VPS的全站默认和网站覆盖只选择已进入代理的流量的目标/源地址族及优先级。双栈首选不可用回退，多IP有序候选、固定源IP与健康冷却共用有界后端，单栈不跨族。

规则更新只接收数据：来源/版本/摘要固定，解析条目/大小/匹配成本有上限，原子切换、离线保留最近成功版本、失败可回滚。面板/API/原生AI/CLI共用业务校验，用户能查看命中和修改业务覆盖；不自动启用额外广告过滤。

任务与真实验收见 [IP-1–IP-6/RULE-1–RULE-5](../superpowers/plans/2026-11-18-dual-stack-address-selection.md)。目前仍在实现规划阶段，三协议与双VPS的IPv6、多IP和目标覆盖实际成功证据未取得。
