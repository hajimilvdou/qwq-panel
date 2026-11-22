# ADR-0001：系统架构基线

- 状态：Accepted（架构提案基线）
- 日期：2026-11-01
- 范围：框架与插件平台，不含具体插件业务

## 决策

| 编号 | 决策 | 原因 | 主要代价 |
|---|---|---|---|
| A01 | Controller + Node Agent + Plugin Runtime | 单机/多节点/探针统一，避免后期重写通信 | 单机也保留少量节点抽象 |
| A02 | Agent 主动发起 mTLS 长连接 | 节点无需公网入站端口，适配 NAT | 需要会话恢复与事件续传 |
| A03 | go-plugin 仅作为本地进程/RPC 底座 | 崩溃隔离、跨语言可能、成熟 | 热切换和沙箱需自行实现 |
| A04 | Platform ABI、go-plugin protocol、Plugin API、State schema 分版本 | 避免无关联升级互相绑架 | 版本治理更严格 |
| A05 | 业务 operation 使用 manifest + JSON Schema envelope | 保持平台 ABI 小且稳定 | 需要 schema 工具保证类型质量 |
| A06 | 宿主与节点操作统一为持久化 Operation | 可恢复、可审计、可幂等 | 比直接 RPC 实现量大 |
| A07 | 首版 Controller 单写 SQLite，事件有界 | 部署简单，避免过早分布式 | 不支持 Controller 多活 |
| A08 | 插件独立 UID + systemd/cgroup；无通用 Exec | go-plugin 不是安全沙箱 | 高权限能力需逐个实现 |
| A09 | 第三方 UI 默认 sandbox iframe | 防止商城插件窃取宿主会话 | 嵌入自由度和开发体验略降 |
| A10 | Core Intent + 独立 Core Driver | 不把上游内部 API 变成公共 ABI | 能力矩阵和转换层需维护 |
| A11 | 移动端仅复用 Client Core | 避免手机承担 Linux 服务与 7×24 任务 | 移动离线业务有限 |
| A12 | 宿主升级使用 socket activation + 重连 | 简单可靠，不伪装零中断 | 长连接会重连 |
| A13 | 宿主侧注册项按 instance + generation 所有，统一自动清理 | 插件崩溃/强杀时仍能撤销路由、订阅、流和授权 | 每次注册增加少量簿记 |
| A14 | `ValidateConfig → ApplyConfig → applied_revision`，热应用可选 | 配置失败不污染当前运行状态 | 插件需实现确认语义 |
| A15 | 卸载使用内置 Finalizer 事务，默认保留数据 | 卸载无残留且不误删用户数据 | 卸载步骤更多 |
| A16 | 事件按可丢失实时流/可靠事件/审计分级背压 | 1G 机器上不会被慢消费者拖垮 | 不同 topic 需定义策略 |
| A17 | 同一插件的实例默认共享插件进程，由 SDK 做命名空间隔离 | 避免多节点产生大量进程与 goroutine | 高风险插件隔离能力较弱 |
| A18 | 小内存优先受控重启，更新前做内存 preflight | 避免蓝绿更新触发 OOM | 部分插件更新有短暂中断 |

## 后果

1. P0–P5 必须先完成插件契约、资源所有权、配置 revision、更新事务、安全和节点基础，业务插件稍后接入。
2. 所有内置插件遵守同样的 ABI 与授权检查；差异仅体现在分发和默认信任策略。
3. 不引入通用 shell/文件/网络回调；新能力以独立、受限、可审计的 Host Capability 增加。
4. 所有插件更新设计必须同时回答“代码如何切”和“状态如何回滚”。
5. 任何宣称支持热更新的功能都必须通过故障注入测试，而不仅是正常路径演示。

## 后续 ADR 触发条件

- 节点规模/写入量超出单 SQLite 容量：评估 PostgreSQL 与任务队列。
- 需要 Controller 高可用：单独设计一致性、fencing、脑裂与备份，不在现有单写上直接加副本。
- 插件需要容器化或跨语言 SDK：只替换进程执行器/SDK，不改变 Platform ABI。
- 代理核心能力出现根本冲突：扩展 Core Intent，而非暴露上游原生配置。
