# 首期代理协议与配套功能设计

- 日期：2026-11-14。
- 状态：Accepted（用户 2026-11-14 确认“设计符合要求”）。X4/X5 已完成的 VLESS v1 基线继续有效，新增组合尚未实现或实测。
- 用户范围：VLESS + TCP + XTLS Vision + REALITY；Hysteria2 + TLS；Shadowsocks2022 + none / simple-obfs HTTP / simple-obfs TLS。其他协议后期再加。
- 必须一起交付：域名接入与 DNS 管理、TLS 证书申请/导入/续期/绑定、部署前检查、客户端配置、状态与回滚。实验在现有两台 VPS 上进行。
- 配套设计：[域名与证书](proxy-prerequisites.md)；现有基础：ADR-0022、core-xray DESIGN、X0 供应链记录、P6 Host Capability 设计。

## 1. 源码与官方资料核验

2026-11-14 读取官方资料，原文缓存位于主工作区 `.cache/sdd/research/protocols-20261114/`。

| 事实 | 证据 | 限制 |
|---|---|---|
| 锁定 Xray 26.11.9 注册 `hysteria` 入站/出站 | [xray.go](https://github.com/XTLS/Xray-core/blob/v26.11.9/infra/conf/xray.go) | 注册并不等于真实互通已验证 |
| Hysteria 配置明确要求 `version == 2`，支持 users 的 auth/level/email | [hysteria.go](https://github.com/XTLS/Xray-core/blob/v26.11.9/infra/conf/hysteria.go) | TLS/QUIC、客户端互通、统计仍须 spike |
| Xray 有独立 SS2022 构建分支及多用户配置；多用户只允许 AES 系列 | [shadowsocks.go](https://github.com/XTLS/Xray-core/blob/v26.11.9/infra/conf/shadowsocks.go) | 不宣称全部 SS2022 cipher 或任意多用户组合都可用 |
| SS2022 是独立 AEAD-2022 协议，密钥须满足对应算法长度 | [SIP022](https://shadowsocks.org/doc/sip022.html) | 不把旧版 SS 方法混进 SS2022 枚举 |
| simple-obfs 提供 obfs-local / obfs-server、HTTP/TLS 混淆；官方标记 Deprecated | [官方 README](https://github.com/shadowsocks/simple-obfs) | 不替换成用户未选的 v2ray-plugin 或 ShadowTLS；通过安全和互通门禁后才可启用 |
| SIP003 插件与 Shadowsocks 核心之间转发 TCP 流 | [SIP003](https://shadowsocks.org/doc/sip003.html) | 不据此宣称 simple-obfs 包装了 UDP |
| Hysteria2 有 TLS、认证、QUIC 与 ACME 配置 | [官方服务端配置](https://v2.hysteria.network/docs/advanced/Full-Server-Config/) | 面板仍统一持有证书生命周期，避免两个证书所有者 |

Xray 二进制继续沿用 X0 已核验的 v26.11.9/676eaf66 基线。simple-obfs 不在已核验包内，须单独完成版本/commit/摘要/许可证核验及必要的安全修正，才能进入运行包；本文不下载或执行它。

## 2. 驱动方案与取舍

**首选：复用 `core.xray`，用可替换适配器渲染三类协议，simple-obfs 作为受控子进程。** 原因是锁定核心源码已包含 Hysteria2 与 SS2022；复用既有安装、秘密、DataDir、配置事务、StatsService 和回滚，避免再维护三套生命周期。

另外两个方案：每协议单独原生驱动，隔离更细但增加进程、更新链与状态对账；替换全部核心为另一个多协议内核，会改变已核验基线且增加迁移成本。只在首选方案的某组合无法通过 spike 时回到方案评审，不自动替换核心或削减验收。

模块边界：

- `sdk/coreapi` 的 v1 类型保持不变；新增版本化的多协议模型和迁移适配器，不把未知字段加入 v1。
- `core.xray` 共享 Apply/进程/快照/统计骨架；协议适配器只负责纯校验、原生配置渲染、能力描述、客户端导出。
- simple-obfs 适配器只接受 `none/http/tls` 枚举与受控 host；执行程序来自验签包的固定路径，不接受命令、额外 argv、环境变量、failover 地址或任意程序路径。
- 域名、证书的业务管理是独立模块；核心只消费已授权的域名/证书绑定，详见配套设计。

## 3. 支持矩阵

| 组合 | 监听传输 | 必需材料 | 首期行为 |
|---|---|---|---|
| VLESS + TCP + Vision + REALITY | TCP | 用户 UUID、REALITY 私钥/公钥、short ID、target/SNI | 面板展示 TCP，驱动按锁定 Xray 的 RAW 名称渲染；沿用 v1 行为 |
| Hysteria2 + TLS | UDP / QUIC | 用户认证凭据、域名/SNI、匹配的有效证书及私钥 | TLS 1.3；启用前验证证书链、域名与 UDP 可达性 |
| SS2022 + none | TCP；UDP 单独门禁 | 服务端与用户的高熵密钥 | 首期多用户选择 `2022-blake3-aes-128-gcm` / `2022-blake3-aes-256-gcm`；不收普通口令替代 PSK |
| SS2022 + obfs-http | TCP | SS2022 密钥、混淆 host | 外层 obfs-server 转发到核心受控回环入站；UDP 默认关闭 |
| SS2022 + obfs-tls | TCP | SS2022 密钥、混淆 host | TLS 外观混淆，不表示经过 CA 验证的 TLS；不要求服务器证书；UDP 默认关闭 |

REALITY target 是经过语法与可达性检查的伪装目标，和本面板管理的自有域名/证书是两种资源。域名绑定不能偷偷改写 REALITY target。SS2022 的混淆 host 同样不能作为“拥有该域名或证书”的证明。

SS2022 UDP、simple-obfs、Hysteria2 的带宽/统计/mark 能力分别声明并实测；某项未验证时仅该项 unavailable，不返回虚构零值或用另一个协议的结果代替。

## 4. 多协议期望模型

新增 Core Intent v2，保留对完整 v1 快照的解码与旧行为：

- 顶层：`schema_version="2"`、必填 `enabled`、`profiles[]`、固定 direct `outbound`。
- `profiles[]`：1–8 个受控入站，可同时启用；公共字段 `id/enabled/listen/port/protocol/users`。协议选择是互斥、严格的联合类型；其他协议的字段一律拒绝。
- 端口仍为 1024–65535；TCP 与 UDP 分别检查占用；外层与回环内层端口均由宿主/驱动分配与校验。UI 不显示内部转发端口。
- 节点总用户数上限 256；ID 在完整快照内唯一，以保持 `qwq-user-<id>` 的统计身份不冲突。一个业务用户可由上层账号模块关联多条协议凭据，核心不承担套餐与角色。
- VLESS 联合成员：RAW/TCP、Vision、REALITY 参数与 UUID 引用。
- Hysteria2 联合成员：认证引用、受控 TLS certificate binding、SNI、经验证后开放的有限 QUIC/带宽参数；首期不开放任意 HTTP 认证 URL、外部认证命令、伪 TCP 或端口跳跃。
- SS2022 联合成员：AES 方法、服务端/用户密钥引用、混淆枚举、混淆 host；禁用旧 SS cipher、DSA 式伪密钥、任意插件和任意路由。
- 配置大小仍上限 1 MiB；严格拒绝未知字段、重复键、无效引用、错误类型和尾随 JSON。引用均由宿主持久化前提取。
- v1 → v2 的迁移显式生成一个 profile，保持端口、用户 ID、tag、enabled、秘密身份与 desired/running 分离；迁移需预演与确认，不在启动时偷偷改写旧配置。
- 现有 `core.apply` 输入仍只传 revision/前置条件。响应与 profile 状态在业务实现卡中定型，Platform ABI v1 不增业务字段。

## 5. 配置、进程与失败处理

一个 Apply job 内：校验期望态 → 校验域名/证书绑定 → 受控揭示本插件配置秘密 → 纯渲染 → 私有候选快照 → 原生预检 → 停旧/启新 → 每个已启用 profile 健康检查 → 提交运行指针 → 发变更事件。

- Xray 与所有 obfs 子进程共享插件单元/cgroup；停止、强杀、更新均回收整个组。
- 只从验签包启动固定二进制；不开通用 shell、不接管系统已有代理服务。
- 配置与证书运行快照 0600，目录 0700；current/previous 指针和摘要原子提交。旧版回滚所需的证书 generation 一并保留，不能只恢复旧 JSON 而留下新私钥/证书。
- 任意 profile 启动失败，恢复完整上一代配置及其 obfs/证书绑定；真实恢复成功后才报告回滚完成。恢复失败明确 `RECOVERY_FAILED`。
- 证书续期成功产生新 generation；消费者预检和重启失败时保持上一代运行证书，不中断既有连接的管理侧证书服务。
- 域名或 DNS 记录与多个 profile 关联时展示影响面；不能删除仍被引用的证书、域名、凭据或配置 generation。
- 资源预算先沿用 256 MiB / 64 PIDs / 4096 FDs；新增 obfs 进程数量与 1C1G 峰值须实测。超预算先优化或限制 profile 数量，不静默抬高资源上限。

## 6. 面板中的完整路径

1. 选择节点与协议，展示本节点已验证能力和缺失项。
2. 添加/选择域名，配置 DNS 提供商并验证解析；Hysteria2 要求普通直连 DNS，禁止误把 HTTP CDN 代理当成 QUIC 转发。
3. Hysteria2 选择有效证书，或直接进入申请/导入流程；显示实际申请、验证、续期状态。VLESS/SS2022 只要求各自真正需要的材料。
4. 在面板生成和管理用户凭据；私钥、PSK、UUID、认证口令只在授权操作中展示或导出一次，其他视图脱敏。
5. 预演显示监听端口、DNS/证书绑定、用户增删、重启和回滚影响；保留 SSH/面板通道。防火墙放行只操作 qwq 自有对象，单独显示并确认。
6. 执行有进度的部署 job；域名、证书、端口、核心、API、真实探测逐项报告。未就绪时保留草稿并指出可执行的修复入口。
7. 导出对应客户端的链接/配置；逐种客户端标记 verified，禁用未验证组合；统计带来源、采样时间、reset epoch 和 unavailable 状态。

## 7. 两台 VPS 的实验与验收

两台现有 VPS 在每轮分配服务端/客户端角色，下一轮交换角色；仍不在 Windows 或测试机编译。使用独立目录、明确临时单元和非特权端口；不接管现有宝塔、SSH、防火墙或代理服务。构建机仍只在项目专属开发目录编译。

每次真实实验先落盘具体版本、域名、端口、角色、命令、回滚与清理清单。DNS/CA 写入只使用该轮专用测试子域和 ACME staging；生产域名/证书/防火墙变更须有具体预演和相应操作授权。

| 门禁 | 内容 | 通过证据 |
|---|---|---|
| PROTO-S0 | 核心/obfs/客户端供应链与许可证 | tag/commit/资产/二进制摘要/运行版本一致 |
| PROTO-S1 | 三协议原生字段、无监听预检、UDS/统计 | 精确字段证据与进程/端口核查 |
| PROTO-S2 | VLESS/Reality/Vision 互通 | 两台 VPS 双角色转发、认证失败、计数器真实增长 |
| PROTO-S3 | Hysteria2/TLS/QUIC 互通 | 正确/错误 SNI、链/私钥/到期拒绝、UDP 转发、统计 |
| PROTO-S4 | SS2022 none/http/tls | 各 AES 方法、多用户、错 PSK、外层混淆、UDP 独立结果；明确客户端版本 |
| PROTO-S5 | 准备工作闭环 | 面板 DNS 记录变更/校验 → staging 签发/导入 → profile 绑定 → 部署 |
| PROTO-S6 | 续期、重启、失败恢复 | 续期换代、候选失败、取消、断连、强杀、回滚、引用保护 |
| PROTO-S7 | 1C1G 与 mark 增量 | RSS/CPU/FD/PIDs、并发 profile、按协议验证 mark；未过不广告 |
| PROTO-S8 | 清理与隔离 | 临时进程/单元/监听/测试 DNS TXT/工作目录逐项清理，现有服务不受影响 |

## 8. 实施顺序与完成定义

1. 完成当前 X4/X5 与 CAP 宿主基础，并收敛 DataDir 父目录遍历问题；不因新增协议跳过现有安全门禁。
2. 实现域名/DNS 管理与证书资源、授权绑定及 bounded renewal；以 fake provider/CA/clock 做失败测试。
3. 引入 Intent v2 与 v1 兼容测试；纯渲染和 schema/secret 提取对齐。
4. 扩展 X6 供应链与两 VPS spike，逐项批准真实可用组合。
5. 完成共用 Apply/回滚/统计和受控 obfs 进程，再实现上述面板路径和客户端导出。
6. PROTO-S0–S8 与既有仓库门禁通过后，首期三协议和准备功能才能一起标记交付。

本文不把 Hysteria2、SS2022、simple-obfs、域名或证书管理标记为已实现；源码支持、设计支持、客户端验证和正式可用四个状态分别记录。用户设计确认不替代供应链、安全、真实互通或生产变更授权门禁。
