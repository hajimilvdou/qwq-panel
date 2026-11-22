# 生产消费者事实与首次预留来源验证

日期：2026-11-18。范围是 Controller 本地消费者来源、实际派发的预留来源及一次性生产 Authority 装配入口，配置保存与业务 forwarder 仍继续施工。

## 当前行为

`PrerequisiteConsumerSource` 每次读取当前 Updater 的真实激活/安装版本、已应用配置和启用状态。完整配置经过 Core Intent v2 严格解码与校验，精确选择 Hysteria2 profile、SNI 和 binding_ref；返回实际配置 revision 和插件 version，不返回配置、秘密或路径。来源的旧 Invocation 只用于范围核对，不重新派发或恢复 operation。

读取前后确认相同 Updater、版本/digest/revision、配置 revision/seq/内容与启用状态。已停用插件、缺配置、错误节点/插件/用途/profile/SNI、无效 TLS/引用、重复 JSON 字段与自报测试字段都拒绝。停用 profile 的合法已提交引用可以用于先配置再绑定，不意味着数据面已启动。

首次 `PrerequisiteReservationSource` 必须带当前 Authority 的私有上下文；从 `CurrentInvocation` 和原 `ReserveBindingArgs` 核对原 operation、完整证书目标、拟建消费者和配置前置版本。额外 `host.plugins:config` 权限依托 `AuthorizeCurrent` 内的真实 Actor，Actor 不出私有对象。计划事实不生成 binding_ref，不冒充已有 profile；原证书登记/CAS预留仍由 Authority 负责。

安装能力使用已有 `core.apply` 的 `operation.api_version=v2` 显式声明，并核对安装/激活状态、真实 manifest ID/version、包摘要与 schema 摘要登记。正式原生驱动、版本化描述符和 schema 必须同步实现；当前正式 `core.xray` 仍为 v1，因此拒绝冒充 Hysteria2 安装事实。SQLite 装配测试中的 v2 声明是明确 fixture，不是签名包或原生驱动成功证据。

Core Intent v2 没有测试信任字段，当前事实固定 `Test=false`。请求 `test=true` 不能升级消费者信任；真实 staging/test 消费的宿主信任来源仍须在原生材料接线中明确实现。

## 实际检查

| 检查 | 结果 |
|---|---|
| 定向消费者与原 HostConfig 来源，native 36803 | PASS，1.519s |
| Controller 全包普通，native 27392 | PASS，9.908s |
| Controller 全包 race，同 native 27392 | PASS，64.731s |
| Controller、hostauth、capability、testsupport 的 vet / staticcheck | PASS |
| tidy-diff、repo_lint、最终 cmd/qwq 构建 | PASS |
| 7 Go 源 SHA / Linux gofmt / 受检格式恢复 | PASS；71680 bytes，SHA `910fa8a0c40048ccf81a68d2e2bfd079e8c37db0d31587c7451114a9256d950a`，token 不变 |

最终日志 `.cache/sdd/gates/prerequisite-sources-final-20261118.log`，SHA `4a580a3990ab1d11858689fedeee99b9ee4b402f7f8bf1a5acaa07dcddb91e83`，真实完整 exit 0、临时目录受检清理，无活动 Root 验证句柄。

保留本阶段3次失败：缺方法的 RED、本机 shell 启动、import 排序的格式 guard。原 bootstrap 原5次失败与用户追加第1次成功分别保留，未使用其第二次机会。DNC core 的原3次失败与独立验证也不调拨或清零。

DNC core 来源 `4257e21488c7f902ae88c2dec5de16b98dbc14c8` 摘取为 `09ebb0de873ea077bc4bc1d87e52b3eb203bd901`，16文件 blob 完全一致；Root 原10个未提交文件在摘取前后逐SHA不变。DNC 后续受检变基 `e4729da6cbb46f1a0a494ba4c2761261f17354f1` 保持同一内容和验证证据。

## 敏感路径自审

按仓库 HANDOFF §11.4 与本会话 AGENTS.md 复核，P0 / P1 / P2 无未处理发现。真实身份/委托/撤权、原参数、节点与消费者范围、当前配置前置条件、私有副本和失效上下文均有实际测试；未引入业务核心表、可序列化运行许可、网络查询、全局依赖或新后台进程。

生产配置保存边界、Authority / DNS / 证书 forwarder 装配、原生 v2 驱动、材料落地和两 VPS 验收尚未完成。全项目目标及新增 IP-1–IP-6 / RULE-1–RULE-5 继续 active。
