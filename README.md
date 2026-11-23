<div align="center">

# qwq

**轻量、安全、AI 原生的模块化 Linux 服务器运维面板**

[![License](https://img.shields.io/badge/license-AGPL--3.0%20%2F%20Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.27+-00ADD8.svg?logo=go&logoColor=white)](go.mod)
[![Platform](https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-2ea44f.svg)](https://github.com/hajimilvdou/qwq-panel/releases)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.1%20(100%2F100)-6BA539.svg)](api/public/v1/openapi.yaml)
[![Releases](https://img.shields.io/github/v/release/hajimilvdou/qwq-panel)](https://github.com/hajimilvdou/qwq-panel/releases)

<sub>专为 1C1G 低配 VPS 到生产服务器打造的下一代模块化控制面 · 零常驻膨胀 · 默认隐身防扫描 · 全能力可插拔</sub>

<sub>注：本项目为独立开源 Linux 运维面板，与阿里通义千问 QwQ 模型无关。</sub>

</div>

---

## 核心特性

### 1. 默认隐身与纵深安全（Security by Default）
- **随机高位端口 + 安全密道 + 静默伪装**：安装即启用随机高位端口、随机入口密道及无服务伪装（默认静默断开 / 可选自定义伪装页）；绑定反代域名后按 Host 自动免密道，裸 IP 探测始终保持隐身。
- **零信任插件隔离**：每个插件独立运行于受 `systemd DynamicUser`、`cgroup v2`、seccomp、`NoNewPrivileges` 与 `SO_PEERCRED`/`SO_PEERPIDFD` 约束的最小权限沙箱；管理端 UI 运行于零内联严格 CSP（`script-src 'self'; style-src 'self'`）不透明源 `iframe`。
- **Ed25519 供应链验签 & 审批闭环**：所有插件包经 Ed25519 签名与逐文件 SHA-256 校验；高危操作内置计划预演（Plan）、分级审批（Approval）、TOTP 二次验证（MFA）与全量审计日志。

### 2. 1C1G 极致轻量架构
- **极速微前端 Shell**：生产首屏 JS 仅 **~35 KiB gzip**，按路由与弹窗懒加载，无重型运行时负担。
- **按需休眠（Scale-to-Zero）**：非后台插件支持空闲自动归零退出，点开由 `systemd .socket` 毫秒级透明唤醒，首页微件直读缓存快照不惊动休眠进程。
- **$O(\log N)$ 路由引擎 & SQLite WAL 双池**：合并区间二分匹配与零指针域名池，1 GiB 内存小鸡亦可流畅运行。

### 3. 全栈内置插件矩阵
| 插件 | 核心能力 |
| :--- | :--- |
| **`core.xray` + `proxy.advanced`** | 支持 **9 大协议**（`VLESS` RAW/gRPC/WS/XHTTP/ENC、`VMess`、`Trojan`、`Shadowsocks` AEAD、`SS-2022`、`Hysteria2`、`AnyTLS v2` 含 UoT、`SOCKS5`、`HTTP`）、**简易/专家双模式**实时 JSON 节点构建器、Reality SNI 自动测速、Cloudflare **WARP** 一键注册与端口/域名解锁分流、链式代理、TCP Brutal、多租户限速及 Base64/Clash/Sing-box 订阅。 |
| **`server.probe`** | 轻量单向零入站服务器探针：内置**经典暖润**与**动态透明水玻璃（Liquid Glass）**双风格、浏览器端 Canvas 智能壁纸压缩（WebP + LQIP 秒开 + 亮度自适应 + 9 宫格焦点）、支持**自定义 `.qwqtheme.zip` 前台主题沙箱热插拔**与独立物理隔离 `/admin` 后台。 |
| **`security.basic`** | `nftables` 防火墙（含 IPv6 NDP 保护与动态端口防锁死）、防伪造日志 `sshd` 暴力破解自动封禁、SSH 密钥与防自锁改端口向导。 |
| **`web.ingress` / `domain.dns` / `tls.certificates`** | 反向代理网关、多 DNS 服务商托管、ACME 自动签发与多协议 TLS 证书集中消费与热重载。 |
| **`ai.relay`** | 多协议 AI 网关（OpenAI / Anthropic / Gemini 互转）、令牌分发、配额计费、兑换码与有界内存防护。 |
| **`containers.docker` / `monitor` / `notify.hub`** | Docker Compose 安全编排与实时尾部日志、系统性能监控、多渠道告警通知中心。 |

### 4. AI 原生运维工作台
- 内置自主运维 Agent 与外部 CLI 适配器（`Claude Code` / `Codex` / `OpenCode` / `DSH` / `ACP`），支持官方登录、自定义 OpenAI/Anthropic 兼容端点、主流 18 家族模型思考强度自动匹配与自定义 effort、独立 Skills/MCP/Prompts 工作区与安全审批托管。

### 5. 开放插件与探针主题生态
- **自定义插件**：提供 `qwq plugin keygen / init / pack / verify` 开发者 CLI、网页 `/apps/install` 拖拽安装与 HTTPS/GitHub Release 远程拉取、以及热生效的开发者 Ed25519 公钥信任管理。详见 [《自定义插件制作、打包、签名与安装规范》](docs/plugins/PLUGIN-AUTHORING-GUIDE.md)。
- **探针前台主题**：支持拖拽 `.qwqtheme.zip` 或 HTTPS URL 一键安装自定义探针前台，运行于独立不透明源沙箱，与后台 `/admin` 物理隔离。详见 [《探针前台展示主题制作规范》](docs/plugins/PROBE-THEME-GUIDE.md)。

---

## 快速安装

> 要求：Linux（`amd64` / `arm64`）、`systemd >= 247`、`cgroup v2`、内存 `>= 1 GiB`。

```bash
curl -fsSL https://raw.githubusercontent.com/hajimilvdou/qwq-panel/main/scripts/install.sh | sudo bash
```

安装完成后终端会自动打印本次生成的**随机高位端口**、**安全密道路径**、本地 SSH 隧道转发命令与一次性初始化链接：

```bash
ssh -L <随机端口>:127.0.0.1:<随机端口> root@<你的服务器IP>
```

建立隧道后在浏览器打开初始化链接即可创建管理员账号并配置 TOTP 二次验证；如需公网直连或绑定反向代理域名，可在登录后的「设置 → 系统 → 面板入口与安全伪装」中无感热切换。

### 常用维护命令

```bash
sudo qwq doctor              # 环境、沙箱、证书与服务健康自检
sudo qwq setup-token         # 重新获取首次初始化链接
sudo qwq recover             # 忘记密码 / MFA 应急恢复
sudo qwq backup create       # 创建加密全量备份（含配置、证书与信任公钥）
sudo qwq rotate-master-key   # 在线轮换主加密密钥（支持热重载）
```

---

## 系统兼容性

| 发行版 | 支持方式 | 验证状态 |
| :--- | :--- | :--- |
| **Ubuntu 24.04 / 26.04 LTS** (`amd64` / `arm64`) | 原生部署（`polkit >= 0.106`，零补丁） | ✅ 完整 KVM E2E 通过 |
| **Debian 12 (bookworm) / 13 (trixie)** | 原生部署（`polkit >= 0.106`，零补丁） | ✅ 完整安装与沙箱通过 |
| **Ubuntu 22.04 LTS / Debian 11 (bullseye)** | `install.sh` 自动验签安装轻量按需补丁 `qwq-compat-polkit` | ✅ 完整安装与沙箱通过 |
| **Rocky Linux 9 / AlmaLinux 9** | 支持自动 `bin_t` SELinux 标签恢复（Enforcing 下建议 `qwq doctor` 核验） | ⚠️ 实验性支持 |

---

## 架构与文档导航

- [系统架构总览](docs/ARCHITECTURE.md) · [架构决策记录 (ADR)](docs/adr/)
- [自定义插件开发与签名发布指南](docs/plugins/PLUGIN-AUTHORING-GUIDE.md)
- [探针前台展示主题开发规范](docs/plugins/PROBE-THEME-GUIDE.md)
- [OpenAPI 3.1 公共契约](api/public/v1/openapi.yaml) · [Platform ABI v1 Proto](api/qwq/platform/v1/platform.proto) · [Manifest Schema v1.3](api/manifest/v1/manifest.schema.json)
- [贡献指南](CONTRIBUTING.md)

---

## 开源协议

本项目采用分区双协议策略（详见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)）：

- **面板宿主与官方内置插件**：`AGPL-3.0-only`（同时提供商业授权选项）
- **插件开发套件（`sdk/`、`web/kit/`）与公共接口契约（`api/`）**：`Apache-2.0`（第三方插件可自由采用闭源或任意开源协议分发）
