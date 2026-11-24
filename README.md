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

从 [GitHub Releases](https://github.com/hajimilvdou/qwq-panel/releases/latest) 拉取已内嵌 Ed25519 发布公钥的官方 `install.sh` 执行安装（将 `v0.1.10` 替换为目标 Release 版本号）：

```bash
# 1. 极简底座安装（仅装面板底座 + 必装安全插件 security.basic，与其他面板共存推荐）
curl -fsSL https://github.com/hajimilvdou/qwq-panel/releases/latest/download/install.sh -o /tmp/qwq-install.sh
sudo bash /tmp/qwq-install.sh --version v0.1.10 --minimal

# 2. 按需同时安装指定官方插件（多插件用逗号分隔，或传 all 安装全部）
sudo bash /tmp/qwq-install.sh --version v0.1.10 --plugins monitor.basic,web.ingress,tls.certificates,containers.docker
```

安装完成后终端会自动打印本次生成的**随机高位端口**、**安全密道路径**、本地 SSH 隧道转发命令与一次性初始化链接：

```bash
ssh -L <随机端口>:127.0.0.1:<随机端口> root@<你的服务器IP>
```

建立隧道后在浏览器打开初始化链接即可创建管理员账号并配置 TOTP 二次验证；如需公网直连或绑定反向代理域名，可在登录后的「设置 → 系统 → 面板入口与安全伪装」中无感热切换。

---

## 升级与回滚

`install.sh` 与 `/opt/qwq/releases/<version>` 发布树均设计为**幂等、不可变、可重复执行**：升级过程不会覆盖 `/etc/qwq/qwq.json`、`/var/lib/qwq` 数据库、端口与安全密道设置、已签发证书或插件数据。

### 1. 在线升级面板底座与官方插件（推荐）

```bash
# （可选但推荐）升级前创建权限 0600 的全量一致备份到 /var/lib/qwq/backups（含主密钥，请异地妥善保管）
sudo qwq backup create

# 拉取最新版官方 install.sh
curl -fsSL https://github.com/hajimilvdou/qwq-panel/releases/latest/download/install.sh -o /tmp/qwq-install.sh

# 方式 A：仅升级面板底座 + 必装插件 security.basic
sudo bash /tmp/qwq-install.sh --version v0.1.10 --minimal

# 方式 B：同步升级面板底座 + 你已启用的可选官方插件（示例）
sudo bash /tmp/qwq-install.sh --version v0.1.10 --plugins monitor.basic,server.probe,web.ingress,tls.certificates,containers.docker
```

升级完成后脚本会自动完成 SHA-256 与 Ed25519 验签、原子切换 `/opt/qwq/current`、重启 `qwq-controller` 并对插件执行原地无损升级。可执行 `sudo qwq doctor` 确认全绿。

### 2. 在面板网页中单独升级插件

你也可以在面板网页升级或补装单个插件，无需重新运行安装脚本：

1. 进入左侧 **「应用中心 → 安装插件」**；
2. 上传对应架构的 `.qwqpkg` 安装包，或直接粘贴 GitHub Release 中的 `.qwqpkg` 下载地址；
3. 核对 Ed25519 签名与权限变更后点击 **「更新」**（更新失败会自动回滚到旧版本）。

### 3. 离线包升级

若目标服务器无法直连 GitHub，可先在本地下载 `qwq-vX.Y.Z-linux-<arch>.tar.gz` 及所需 `.qwqpkg` 到服务器同一目录后执行：

```bash
sudo bash /tmp/qwq-install.sh --offline ./qwq-v0.1.10-linux-amd64.tar.gz --minimal
# 如需同时离线升级可选插件：
sudo bash /tmp/qwq-install.sh --offline ./qwq-v0.1.10-linux-amd64.tar.gz --plugins web.ingress,containers.docker --plugin-dir ./
```

### 4. 版本回滚

- **面板底座回滚**：旧版本发布树保留在 `/opt/qwq/releases/` 下，如需退回上一版本（例如 `v0.1.9`），直接对目标旧版本再次运行安装脚本即可：
  ```bash
  sudo bash /tmp/qwq-install.sh --version v0.1.9 --minimal
  ```
- **单个插件回滚**：在面板 **「应用中心 → 选择对应插件 → 回滚」** 中一键切回上一版本。

---

### 常用维护命令

```bash
sudo qwq doctor              # 环境、沙箱、证书与服务健康自检
sudo qwq setup-token         # 重新获取首次初始化链接
sudo qwq access show         # 查看当前实时监听端口、安全密道与救援入口
sudo qwq access reset        # 忘记密道或误配域名时应急重置面板入口
sudo qwq recover             # 忘记密码 / MFA 应急恢复（支持交互式输入）
sudo qwq backup create       # 创建权限 0600 的全量一致备份（含数据库、主密钥、配置与证书）
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
