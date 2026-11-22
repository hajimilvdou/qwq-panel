# qwq-panel：原生面向 AI Agent 操控的模块化服务器运维面板

> 与阿里通义千问的 QwQ 模型无关。

**厌烦传统服务器面板里密密麻麻的几十页菜单和复杂配置？**  
**qwq 从底层就是为 AI Agent 原生操控而设计的 Linux 运维面板** —— 你可以像普通面板一样打开浏览器点选管理，也可以**把整台服务器的面板全权交给 AI 来替你操作**：装网站、配 HTTPS、加固 SSH 防火墙、查内存飙升、管容器、配告警、建代理节点，全都可以用自然语言让 AI 自动完成，高危操作自动弹出「变更预览 + 一键审批」，安全又省心。

---

## 🤖 核心亮点：原生底层适配 AI Agent，面板可全权交给 AI 操作

不同于在传统面板外面生硬套一层聊天框，**qwq 的每一项宿主能力与插件功能，底层都原生按 AI Agent 标准建模**：

- **内置 7 个结构化 Agent 原生工具接口**（`/api/v1/agent/{find_actions,describe_action,read,plan,execute,wait,cancel}`）与 **101 条严格校验的 OpenAPI v1 契约**：AI 不需要靠猜命令或硬编码 SSH 脚本，直接发现可用能力、读取参数 Schema 并精准调用。
- **先出计划（Plan），再执行（Execute）**：对防火墙、反代、证书、SSH 等变更，AI 可先生成结构化变更预览与影响说明；高危动作自动进入**人工一键审批（Approvals）**，确认后才落地，不瞎改系统。
- **全链路幂等、可审计、可回滚**：每次 AI 操作都有独立 `Idempotency-Key`、完整操作流水（Operations / Jobs）与不可篡改审计日志，配合细粒度作用域的 **Service Account / 授权委托**，随时可控、随时可撤权。
- **既支持内置原生 Agent 会话，也支持外部 CLI Agent（Claude Code / Codex / 自定义 MCP 等）安全接入**：不想研究 Nginx 配置、ACME 证书、nftables 规则或 Docker Compose 参数的小白，直接把需求告诉 AI 即可搞定。

---

## 🧱 极简安全底座 + 强隔离可选插件（1C1G VPS 轻松跑）

- **极简必装底座**：仅包含宿主控制器（`qwq`）、最小权限特权助手（`qwq-privileged` / `qwq-capability`）、内嵌 Web Shell，以及默认必装的基础安全插件 `security.basic`（防火墙 / 防失联改 SSH / 公钥管理 / 防爆破）。
- **10 款按需选装官方插件**：全部独立打包为 Ed25519 签名的 `.qwqpkg` 插件包，安装时可交互勾选，装完后也能在面板内随时一键加装或卸载；每个插件运行在独立的 `systemd DynamicUser + seccomp + cgroup v2` 沙箱中。
- **与现有环境零冲突共存**：绝不改动宿主机已有的 Nginx / Caddy / UFW / firewalld / 宝塔；默认仅监听 `127.0.0.1:8443`，推荐通过 SSH 隧道或自配反代访问。
- **可复现构建 + Ed25519 全链路验签**：每次发版在 GitHub Actions 同一提交构建两遍逐字节比对 `SHA256SUMS`，并由离线发布密钥签名。

---

## 🚀 一键快速安装

从 [GitHub Releases](https://github.com/hajimilvdou/qwq-panel/releases) 下载对应版本的 `install.sh`（内置 Ed25519 发布公钥验签）并运行：

```bash
VERSION=v0.1.1
curl -fsSL "https://github.com/hajimilvdou/qwq-panel/releases/download/${VERSION}/install.sh" -o install.sh
sudo bash install.sh --version "${VERSION}"
```

安装脚本会自动完成：
1. 自动识别 CPU 架构（`linux/amd64` / `linux/arm64`）与系统环境；
2. 校验 `SHA256SUMS.sig` Ed25519 签名与文件 SHA-256；
3. **自动识别原生/旧版系统**：Debian 12+ / Ubuntu 24.04+ 保持 100% 原生零补丁；若检测到 Ubuntu 22.04 或 Debian 11 缺少 `polkit >= 0.106`，自动下载并验签安装独立兼容补丁 `qwq-compat-polkit`，做到与原生完全一致的插件沙箱体验；
4. 在终端弹出可选插件勾选菜单（也支持非交互参数）：

```bash
# 仅安装极简底座 + security.basic
sudo bash install.sh --version "${VERSION}" --minimal

# 指定按需安装的插件（逗号分隔或 all）
sudo bash install.sh --version "${VERSION}" --plugins monitor.basic,web.ingress,notify.hub
```

安装完成后，按终端打印的一次性初始化链接通过 SSH 隧道打开面板：

```bash
ssh -L 8443:127.0.0.1:8443 root@<你的服务器IP>
```

---

## 📦 官方可选插件（按需下载）

| 插件 ID | 功能说明 |
|---|---|
| `security.basic` | **默认必装** · 基础安全防护（防火墙 / 防失联改 SSH / 公钥 / 防爆破） |
| `monitor.basic` | 基础监控（CPU / 内存 / 磁盘 / 网络实时趋势微件） |
| `server.probe` | 服务器探针中心（多机单向安全探针 / 90 天 SLA / 三网拨测） |
| `domain.dns` | 域名与 DNS 管理（Cloudflare / 阿里云解析管理，按需唤醒） |
| `tls.certificates` | TLS 证书与 ACME DNS-01 自动签发续期（按需唤醒） |
| `core.xray` | Xray 三协议核心驱动（VLESS+REALITY / Hysteria2 / SS2022） |
| `proxy.advanced` | 高级代理多用户配额、HTB 限速与订阅中心（自动补齐 `core.xray`） |
| `ai.relay` | AI API 聚合中转、四协议互转与自服务分发门户 |
| `web.ingress` | 轻量反向代理与站点托管（内置 Go 反代 / Caddy & Nginx 渲染 / 快照回滚） |
| `containers.docker` | 轻量容器与 Compose 管理（直连 Unix Socket / 动态限额 / 有界日志） |
| `notify.hub` | 统一告警与通知中枢（Telegram / 飞书 / 钉钉 / 企微 / Discord / SMTP / Webhook） |

每次发版均同步发布 `plugins-index.json` 元数据索引与各架构 `.qwqpkg` 签名包，可通过 `qwqctl verify` 或宿主信任根（`/etc/qwq/trust/`）验签。

---

## 🖥️ 支持平台（6 大主流发行版全部真机/虚拟机实测通过）

要求：`systemd ≥ 247`、`cgroup v2`、内存 ≥ 1 GiB（`linux/amd64` / `linux/arm64`）。

- **原生支持系统（推荐，零额外补丁）**：**Ubuntu 24.04 LTS / Ubuntu 26.04 LTS / Debian 12 / Debian 13** —— 原生具备 `polkit >= 0.106`（支持 JS 规则），`install.sh` **绝不下载也不安装**任何兼容补丁，保持 100% 原生运行。
- **旧版系统自动补丁适配（体验与原生一致）**：**Ubuntu 22.04 LTS / Debian 11** —— 系统自带旧版 `polkit 0.105`（不读 JS 规则）或缺少 `polkitd`。`install.sh` 会自动检测并下载经 Ed25519 验签的独立兼容补丁 `qwq-compat-polkit`（按需 socket 激活、零常驻内存、仅校验 `qwq` 用户且严格白名单限定 `qwq-plugin@*` 单元，权限边界与原生 polkit JS 规则完全等价）。

| 平台 | 运行模式 | 实测状态 | 说明 |
|---|---|---|---|
| **Ubuntu 24.04 LTS** (amd64 / arm64) | 原生（零补丁） | ✅ 已实测通过 | 主力推荐平台，GitHub Actions 真 KVM 完整 E2E 全绿 |
| **Ubuntu 26.04 LTS** | 原生（零补丁） | ✅ 已实测通过 | 内核 7.0 + `SO_PEERPIDFD` + `polkitd 127` + `systemd 259` 全绿 |
| **Debian 12 (bookworm)** | 原生（零补丁） | ✅ 已实测通过 | `systemd 252` + `polkitd 122`，完整安装/沙箱/卸载全绿 |
| **Debian 13 (trixie)** | 原生（零补丁） | ✅ 已实测通过 | `systemd 257` + `polkitd 126`，完整安装/沙箱/卸载全绿 |
| **Ubuntu 22.04 LTS** | 自动补丁 (`qwq-compat-polkit`) | ✅ 已实测通过 | `install.sh` 自动下发补丁绕过 `polkit 0.105`，插件沙箱与原生一致 |
| **Debian 11 (bullseye)** | 自动补丁 (`qwq-compat-polkit`) | ✅ 已实测通过 | `systemd 247` + `install.sh` 自动下发补丁，插件沙箱与原生一致 |
| Rocky 9 / Alma 9 | 原生（待真机验证） | ⚠️ 未真机实测 | SELinux enforcing 下需按 `qwq doctor` 提示核对文件标签 |

---

## 📚 文档与开发

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — 系统架构说明
- [docs/adr/](docs/adr/) — 架构决策记录（ADR）
- [docs/operations/](docs/operations/) — 安装、发布、备份与运维手册（发布流程见 [docs/operations/release.md](docs/operations/release.md)）
- [api/qwq/platform/v1/platform.proto](api/qwq/platform/v1/platform.proto) — Platform ABI v1 协议定义
- [api/manifest/v1/manifest.schema.json](api/manifest/v1/manifest.schema.json) — 插件 Manifest 规范
- [api/public/v1/openapi.yaml](api/public/v1/openapi.yaml) — 公共 REST API & AI Agent 工具契约（OpenAPI 3.1）
- [CONTRIBUTING.md](CONTRIBUTING.md) — 开发环境与贡献说明

### 从源码构建

```bash
# 1. 初始化项目内工具链（不污染系统环境）
source scripts/dev-env.sh
bash scripts/bootstrap-tools.sh

# 2. 运行门禁检查与测试
bash scripts/check.sh

# 3. 构建并嵌入前端 Web Shell
(cd web && npm ci && npm run build)
bash scripts/embed-web.sh
```

---

## 📄 许可证

本仓库按目录分区许可（详见 [NOTICE](NOTICE) 与 [CONTRIBUTING.md](CONTRIBUTING.md)）：

- `api/`、`sdk/`、`web/kit/`：**Apache-2.0**（插件仅依赖 `sdk/`，可采用任意许可证）
- 其余宿主、Web Shell 与内置插件：**AGPL-3.0-only**（同时提供商业授权）
