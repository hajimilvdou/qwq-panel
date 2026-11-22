# Core Intent v2

本包定义已批准三协议的完整期望模型，导入路径为 `github.com/qwq-panel/qwq/sdk/coreapi/v2`，Go package 名仍为 `coreapi`。与 v1 同时导入时请使用 `corev2` 别名。

## 入口

| 入口 | 职责 |
|---|---|
| `Decode([]byte) (*Intent, error)` | 严格 wire 解析；未知字段、重复键、null、大小写回退、整数错误与尾随 JSON 拒绝 |
| `Validate(*Intent) error` | 完整快照、协议/凭据联合、引用形状、用户上限、监听冲突的纯校验 |
| `Listeners(*Intent) ([]Listener, error)` | 先完整校验，再返回实际启用的外部 TCP/UDP 监听声明 |
| `FromV1(*v1.Intent) (*Intent, error)` | 深拷贝的显式迁移候选；不保存、不启动、不揭示材料 |

两版本共用 SDK 内部 token 解码器和 v1 纯规则，不依赖宿主包，不增加 Platform ABI 字段。错误仍为 `INVALID_INTENT`，violations 使用 RFC 6901 指针；不回显输入值。语法解析与语义校验是两步，调用方必须同时执行。

## 联合字段

顶层固定 `schema_version="2"`、显式 `enabled`、1–8 个 `profiles` 和 `outbound.type="direct"`。每个 profile 都有 `id/enabled/listen/port/protocol/users`，再按下表选择唯一成员。其他成员与其他类型的用户凭据必须完全缺失，不能传 null 或空对象表示停用。

| protocol | 唯一配置成员 | 用户凭据 | 外部传输 |
|---|---|---|---|
| `vless` | `vless.transport="raw"`、`flow="xtls-rprx-vision"`、既有 REALITY `security` | `uuid` secret 引用 | TCP |
| `hysteria2` | `hysteria2.tls.binding_ref/server_name` | `auth` secret 引用 | UDP |
| `shadowsocks2022` | `method/server_key/obfs`、可选 `udp` | `psk` secret 引用 | TCP；仅 none 可另外声明 UDP |

SS 方法仅 `2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`。混淆 mode 为 `none/http/tls`；none 不接受 host，http/tls 要求 ASCII DNS host。`udp` 默认 false，simple-obfs 组合永远拒绝 true。host 不证明域名或证书归属。

Hysteria2 的 binding_ref 是 1–128 位 `[A-Za-z0-9_.-]` 字符组成的宿主稳定引用。它没有授权含义；运行接口必须验证调用 plugin/profile/node/purpose、operation 与消费 SNI，再固定 generation/policy_revision。模型不传证书路径、私钥、secret owner、证书最新代次或 insecure 开关。

监听端口为 1024–65535。TCP/UDP 分别检查，同端口的 IPv4 mapped 地址与 IPv4 地址视为相同；IPv6 `::` 按可能双栈处理。停用 profile 不声明端口，但其配置材料形状仍完整校验；顶层停用不掩盖 enabled profiles 之间的冲突。

profile ID 在 profiles 内唯一，用户 ID 在整个快照内唯一，包括停用 profiles 的用户。两类身份沿用 `qwq-in-` 与 `qwq-user-` 前缀，所以允许 profile 和用户合法同名，保持全部合法 v1 快照可迁移。节点总用户数包含停用 profiles，最多 256。

## 显式迁移

`FromV1` 先执行完整 v1 校验，生成一个 ID/监听/用户/REALITY 相同的 VLESS profile。新 profile.enabled=true，顶层 enabled 保持原值；所有切片与指针独立，secret ID 不变。

调用方在预演与确认之后才保存新 desired revision；旧 running generation 保持到显式 Apply。两版本的 Decode 均不会自动迁移或宽松回退。

## 验证状态

2026-11-15 构建通路恢复后，本包与共享解析器、v1 回归的普通/race/vet/staticcheck 通过；新增 24 项顶层测试具有实际 pass 事件。仓库 check.sh 18/18 通过，Xray 全包普通/race 回归通过，SDK 多架构 vet 通过。

30 秒 fuzz 命令通过，但日志只记录 5 次执行；随后使用 `-fuzztime=100x -timeout=60s` 定向复核，实际完成 113 次执行、PASS。不能把这些证据扩大为真实协议或证书运行验收。日志：主工作区 `.cache/sdd/gates/g23-core-intent-v2-complete.log` 与 `proto-i2-fuzz-count.log`。

该模型只表示用户意图。秘密存在性、owner/purpose、PSK 长度与生成质量、证书链/SAN/到期、DNS only、实际端口、原生渲染、协议可用性、客户端互通与统计仍由宿主、驱动和 PROTO-S0–S8 分别验证。当前运行插件继续只接受 v1。
