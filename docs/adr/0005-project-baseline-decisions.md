# ADR-0005：项目基线决策

- 状态：Accepted
- 日期：2026-11-01
- 关联：`IMPLEMENTATION-PLAN.md` §1；HANDOFF §9.1

## 决策

| 编号 | 事项 | 决定 |
|---|---|---|
| Q1 | 名称与 module path | 产品名 **qwq**（全小写）。宿主模块 `github.com/qwq-panel/qwq`，SDK 模块 `github.com/qwq-panel/qwq/sdk`。GitHub 用户名 `qwq` 已被个人账号占用，按发起人要求组织名用 `qwq-panel`（可用，需发起人注册）。曾考虑的 Cove 因同领域已有产品而放弃 |
| Q2 | 许可证 | 宿主 **AGPL-3.0-only + 商业授权**（双许可）；SDK 与公共契约 **Apache-2.0**；外部贡献须签 CLA |
| Q3 | 托管与流程 | GitHub + GitHub Actions；`main` 分支保护，功能分支 + PR，squash 合并（流程为默认值，可调整） |
| Q4 | 目标平台 | Debian 12+、Ubuntu 22.04 LTS+、Rocky/Alma 9+；systemd ≥ 249，cgroup v2；首批架构 `linux/amd64`、`linux/arm64` |
| Q5 | Linux 测试环境 | 两台发起人提供的 VPS（`IMPLEMENTATION-PLAN.md` §2）：构建机（Ubuntu 20.04、systemd 245、3C4G）编译与测试，开发机不装编译工具链；测试机（Ubuntu 24.04、systemd 255、cgroup v2、1 vCPU / 961 MiB，与宝塔面板共存）满足 Q4，用于 P2 沙箱 spike 与 1C1G 实测 |
| Q6 | TLS | 宿主内置：有域名时自动申请 ACME 证书（HTTP-01 或 TLS-ALPN-01）；只有 IP 时生成自签名证书并在安装输出中打印指纹；可放在反代之后，只信任已配置的反代地址 |
| Q7 | 身份 | 首版多用户 + 角色（管理员、运维、只读）+ TOTP；数据模型预留 WebAuthn 与 OIDC。Passkey 需要域名（RP ID），只用 IP 访问时不可用 |
| Q8 | 首版范围 | 首版只交付 `standalone`；多节点在首版之后 |
| Q11 | 首版插件 | 基础监控 + 基础防护（防火墙、登录防爆破、SSH 端口与登录方式、密钥与密码管理），其他安全功能放到之后的安全插件；详见 ADR-0009 |

## Q2 的落地：许可证分区

AGPL 的目的是"修改宿主后必须公开源码，否则购买商业授权"。插件要能用任何许可证（包括闭源收费），所以插件编译时用到的代码必须是 Apache-2.0，并且放在独立的 Go 模块里，避免插件依赖 AGPL 模块。

| 部分 | 位置 | 许可证 |
|---|---|---|
| 公共契约：proto、manifest schema、OpenAPI | `api/` | Apache-2.0 |
| SDK 模块：生成的 Go 代码、`pluginsdk`、`manifest` 校验、`coreapi` | `sdk/`（独立 `go.mod`） | Apache-2.0 |
| Liquid UI Kit（插件 UI 会打包一份） | 正式版位于 `web/kit/` | Apache-2.0 |
| 宿主：`cmd/`、`internal/`、`web/shell/`、内置插件 | 其余全部 | AGPL-3.0-only + 商业授权 |

- 宿主模块依赖 SDK 模块（Apache 代码并入 AGPL 程序是兼容的）；SDK 模块不得依赖宿主模块。
- 双许可的前提是作者持有全部代码的版权：接受第一个外部 PR 前，必须有 CONTRIBUTING.md 和 CLA（如 GitHub 上的 CLA Assistant）。
- 选 `-only`：CLA 已保留作者重新授权的能力，不需要自动接受未来的 GPL 版本。
- 本 ADR 不是法律意见。LICENSE、CLA 与商业授权条款在公开发布前应由律师审阅（IMPLEMENTATION-PLAN Q9）。

## Q1 的风险与标识符映射

已知的同名使用：

- **阿里通义千问团队的推理模型系列 QwQ**（`QwenLM/QwQ`，如 QwQ-32B）。本项目有 AI 操作面，用户可能误以为面板来自阿里或绑定该模型；搜索"qwq"时结果会被该模型占据。对外介绍时建议固定写法"qwq panel / qwq 面板"，并在 README 中说明与 Qwen 无关。
- "qwq" 也是常见的网络颜文字，品牌好记，但单独搜索时难以检索到本项目。

公开发布前需做商标检索（国内 CNIPA、美国 USPTO，IMPLEMENTATION-PLAN Q10）。若检索后改名，只需按下表再替换一次。

文档与契约原先使用占位前缀 `panel`。P0-T2b 在基线提交之后按下表一次性替换，作为单独一个提交，便于审阅和回退：

| 原占位 | 改为 |
|---|---|
| proto package `panel.platform.v1`，目录 `api/panel/platform/v1/` | `qwq.platform.v1`，`api/qwq/platform/v1/` |
| 节点协议目录 `api/panel/node/v1/` | `api/qwq/node/v1/` |
| manifest `$id` `urn:panel:plugin-manifest:v1` | `urn:qwq:plugin-manifest:v1` |
| 二进制 `panel`、`panelctl` | `qwq`、`qwqctl` |
| systemd 单元 `panel-controller`、`panel-agent`、`panel-privileged`、`panel-plugin@<id>` | `qwq-controller`、`qwq-agent`、`qwq-privileged`、`qwq-plugin@<id>` |
| 插件固定用户 `panel-p-<hash>` | `qwq-p-<hash>` |
| 路径 `/opt/panel`、`/var/lib/panel`、`/etc/panel`、`/var/log/panel`、`/run/panel` | `/opt/qwq`、`/var/lib/qwq`、`/etc/qwq`、`/var/log/qwq`、`/run/qwq` |
| 节点证书 URI SAN `panel://node/<id>` | `qwq://node/<id>` |
| 内置发布者 `panel-builtin` | `qwq-builtin` |
| 界面中的占位品牌"面板 · 产品名待定" | "qwq" |

中文正文中表示"面板"这个概念的词不替换；`archive/` 不替换。

## Q8 的落地：首版单机

- 保留节点协议边界：standalone 中 Controller 与本机 Agent 走同一套节点协议（经本地 UDS），公共 API 保留 `node_id`（单机时只有一个节点 `local`）。以后加多节点不改 API 和插件契约。
- ADR-0002 不变：standalone 的本机 Agent 同时运行 `node` 与 `controller` 两类插件。
- 推到首版之后：enroll、mTLS、spool、远程操作、节点本地策略、`controller` 与 `agent` 两种安装角色、路线图第 1 项中的"探针形态"。
- 施工计划中 P4 移到首版之后；其余阶段顺序不变。首版包含哪些业务插件，在 P6 开始前另定。
