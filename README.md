<div align="center">

# qwq

**轻量、安全、AI 原生的模块化 Linux 服务器运维面板**

[![Release](https://img.shields.io/github/v/release/hajimilvdou/qwq-panel?color=2ea44f)](https://github.com/hajimilvdou/qwq-panel/releases/latest)
[![Platform](https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-blue)](https://github.com/hajimilvdou/qwq-panel/releases/latest)
[![Go](https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go&logoColor=white)](go.mod)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.1%20(100%2F100)-6BA539)](api/public/v1/openapi.yaml)
[![License](https://img.shields.io/badge/License-AGPL--3.0%20%2F%20Apache--2.0-orange)](LICENSE)

<sub>面向 1C1G 低配 VPS 到生产服务器的现代控制面 · 默认隐身防扫描 · 按需休眠零膨胀 · 原生 AI 运维</sub>

<sub>注：本项目为独立开源 Linux 运维面板，与阿里通义千问 QwQ 模型无关。</sub>

</div>

---

## 核心亮点

- **默认隐身与最小权限安全**：安装即启用随机高位端口、随机入口密道与静默伪装；插件独立运行于 `systemd DynamicUser` + `cgroup v2` + `seccomp` 沙箱与严格零内联 CSP `iframe`；发布包全程 Ed25519 验签，高危操作内置计划预演、分级审批与可选 TOTP 二步验证。
- **1C1G 极致轻量**：首屏前端仅约 **35 KiB gzip**，非后台插件空闲自动归零休眠（Scale-to-Zero），由 `systemd .socket` 毫秒级透明唤醒，适合低配机器长期稳定运行。
- **AI 原生运维工作台**：内置通用服务器 + 原生面板操控 Agent（按会话权限模式分级审批），同时兼容 `Claude Code` / `Codex` / `OpenCode` / `DSH` / `ACP`；支持主流大模型思考强度与上下文窗口自动识别、用户与 Agent 双向**交互文件夹**、以及会话导出与管理。
- **开放插件与主题生态**：底座极简起步，10 款官方插件按需热插拔；提供 `qwq plugin` 开发者 CLI 与独立沙箱探针主题（`.qwqtheme.zip`）。

---

## 快速安装

> 系统要求：Linux（`amd64` / `arm64`）、`systemd >= 247`、`cgroup v2`、内存 `>= 1 GiB`。

### 一键安装（自动获取最新正式版）

```bash
curl -fsSL https://github.com/hajimilvdou/qwq-panel/releases/latest/download/install.sh | sudo bash
```

> 安装程序默认监听 `0.0.0.0:<随机高位端口>`、启用随机安全密道与静默伪装，并自动识别系统防火墙（`ufw` / `firewalld` / `nftables` / `iptables`）放行面板端口；交互终端中**直接回车**仅装面板底座 + `security.basic`，也可输入编号按需勾选插件。

### 便捷一键命令（非交互）

```bash
# 极简底座（仅面板 + 必装安全插件）
curl -fsSL https://github.com/hajimilvdou/qwq-panel/releases/latest/download/install.sh | sudo bash -s -- --minimal

# 底座 + 指定官方插件（逗号分隔，或 --plugins all 安装全部）
curl -fsSL https://github.com/hajimilvdou/qwq-panel/releases/latest/download/install.sh | sudo bash -s -- --plugins proxy.advanced,web.ingress,tls.certificates,containers.docker
```

**首次登录**：安装完成后直接在浏览器打开终端打印的公网初始化链接即可创建管理员账号（如云厂商控制台单独开启了安全组/云防火墙，请放行对应 TCP 端口；2FA 为可选项，按需开启）。如需仅本机回环监听，可追加 `--listen 127.0.0.1`；登录后也可随时在 **「设置 → 系统 → 面板入口与安全伪装」** 热切换监听地址、端口或反向代理域名。

---

## 官方插件一览

> **内置实时监控**：面板主页原生自带主机 CPU / 内存 / 磁盘 / 网络实时状态、Top 占用进程悬停洞察与平滑趋势曲线，无需额外安装监控插件。

| 插件 ID | 安装方式 | 核心能力 |
| :--- | :---: | :--- |
| `security.basic` | **默认必装** | `nftables` 防火墙（含 IPv6 NDP 与防锁死保护）、`sshd` 防爆破、SSH 密钥与安全改端口、一键接管/还原 `ufw`/`firewalld`/`fail2ban` |
| `proxy.advanced` | 可选 | **内置 Xray v26.11.9 引擎**，一站式全协议建节点（VLESS Reality / VMess / Trojan / SS2022 / Hysteria2 / AnyTLS）、WARP 解锁、多用户限速与 Clash/sing-box/Base64 订阅 |
| `server.probe` | 可选 | 单向零入站多机探针、SLA 与三网拨测、双内置风格及 `.qwqtheme.zip` 自定义主题 |
| `web.ingress` | 可选 | 轻量反向代理与站点托管（内置 Go 反代 / Caddy & Nginx 渲染 / 快照回滚） |
| `domain.dns` | 可选 | Cloudflare / 阿里云等 DNS 解析集中管理 |
| `tls.certificates` | 可选 | ACME（DNS-01 / HTTP-01）证书自动签发、续期与多插件热分发 |
| `containers.docker` | 可选 | Docker 容器与 Compose 安全编排、动态限额与实时尾部日志 |
| `ai.relay` | 可选 | OpenAI / Anthropic / Gemini 多协议中转、令牌配额计费与自服务分发门户 |
| `notify.hub` | 可选 | Telegram / 飞书 / 钉钉 / 企微 / Discord / SMTP / Webhook 统一告警通知 |

> 未在安装时勾选的插件，可随时在面板 **「应用中心」** 一键在线补装、更新、回滚或卸载。

---

## 升级、回滚与维护

安装脚本与 `/opt/qwq/releases/` 目录均为**幂等不可变设计**，升级不会覆盖数据库、配置、端口密道、证书或插件数据。

```bash
# （推荐）升级前创建全量加密备份
sudo qwq backup create

# 一键原地升级到最新正式版（底座 + 必装安全插件）
curl -fsSL https://github.com/hajimilvdou/qwq-panel/releases/latest/download/install.sh | sudo bash -s -- --minimal

# 如需连同已启用的可选插件一起升级，将 --minimal 替换为 --plugins <逗号分隔ID> 或 --plugins all
```

<details>
<summary><b>展开查看：指定版本安装 / 版本回滚 / 离线安装 / 网页单插件升级</b></summary>

- **指定版本或回滚旧版**：追加 `--version <tag>` 即可（例如 `--version v0.1.15`）：
  ```bash
  curl -fsSL https://github.com/hajimilvdou/qwq-panel/releases/latest/download/install.sh | sudo bash -s -- --version <目标版本号> --minimal
  ```
- **面板网页升级或回滚单个插件**：进入 **「应用中心」** 选择插件，支持在线拉取或上传 `.qwqpkg` 更新，失败自动回滚，也可在版本页一键回退。
- **离线安装 / 升级**：从 [Releases](https://github.com/hajimilvdou/qwq-panel/releases) 下载对应架构的主包与 `.qwqpkg` 到同一目录后解包出 `install.sh` 或直接执行：
  ```bash
  sudo bash install.sh --offline ./qwq-<版本号>-linux-<amd64|arm64>.tar.gz --minimal
  # 同时离线安装可选插件：追加 --plugins <插件ID列表> --plugin-dir ./
  ```

</details>

### 常用维护命令

```bash
sudo qwq doctor              # 环境、沙箱、证书与服务健康自检
sudo qwq setup-token         # 重新生成首次初始化链接
sudo qwq access show         # 查看当前监听端口、安全密道与救援入口
sudo qwq access reset        # 忘记密道或域名误配时重置面板入口
sudo qwq recover             # 忘记密码或 2FA 应急恢复
sudo qwq backup create       # 创建 0600 权限全量一致备份（含主密钥，请妥善异地保管）
sudo qwq rotate-master-key   # 在线轮换主加密密钥
```

---

## 系统兼容性

| 发行版 | 支持方式 | 状态 |
| :--- | :--- | :---: |
| **Ubuntu 24.04 / 26.04 LTS**（`amd64` / `arm64`） | 原生部署（`polkit >= 0.106`，零补丁） | ✅ 已验证 |
| **Debian 12 / 13**（`amd64` / `arm64`） | 原生部署（`polkit >= 0.106`，零补丁） | ✅ 已验证 |
| **Ubuntu 22.04 LTS / Debian 11** | `install.sh` 自动验签安装 `qwq-compat-polkit` 兼容补丁 | ✅ 已验证 |
| **Rocky Linux 9 / AlmaLinux 9** | 支持 SELinux `bin_t` 标签恢复（建议用 `qwq doctor` 核验） | ⚠️ 实验性 |

---

## 文档与开源协议

- **开发与架构**：[系统架构总览](docs/ARCHITECTURE.md) · [ADR 决策记录](docs/adr/) · [自定义插件开发规范](docs/plugins/PLUGIN-AUTHORING-GUIDE.md) · [探针前台主题规范](docs/plugins/PROBE-THEME-GUIDE.md) · [贡献指南](CONTRIBUTING.md)
- **接口契约**：[OpenAPI 3.1](api/public/v1/openapi.yaml) · [Platform ABI v1 Proto](api/qwq/platform/v1/platform.proto) · [Manifest Schema v1.3](api/manifest/v1/manifest.schema.json)
- **开源协议**：面板宿主与官方插件采用 **`AGPL-3.0-only`**（支持商业授权）；插件开发套件（`sdk/`、`web/kit/`）与公共契约（`api/`）采用 **`Apache-2.0`**（第三方插件可自由选择开源或闭源协议）。详见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。
