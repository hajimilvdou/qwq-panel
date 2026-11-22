# qwq-panel：模块化服务器运维面板

> 与阿里通义千问的 QwQ 模型无关。

**qwq** 是一个面向 Linux 服务器（低至 1C1G VPS 可稳定运行）的现代化模块化运维面板，采用「极简安全底座 + 强隔离可选插件」分层架构：

- **极简必装底座**：仅包含宿主控制器（`qwq`）、最小权限特权助手（`qwq-privileged` / `qwq-capability`）、内嵌 Web Shell，以及默认必装的基础安全插件 `security.basic`（防火墙 / 防失联改 SSH / 公钥管理 / 防爆破）。
- **按需选装官方插件**：其余 10 款官方插件均打包为独立的 Ed25519 签名 `.qwqpkg` 产物，可在安装时交互勾选，也可在安装后随时按需补装或卸载。
- **与现有环境共存**：不改动现有 nginx / ufw / firewalld；默认仅监听 `127.0.0.1:8443`，推荐经 SSH 隧道或自配反代访问。
- **AI 原生操作面**：所有写操作统一经审批与审计日志流水线，支持原生 Agent 与外部 CLI Agent 沙箱接入。

---

## 快速安装

从 [GitHub Releases](https://github.com/hajimilvdou/qwq-panel/releases) 下载对应版本的 `install.sh`（内置 Ed25519 发布公钥验签）并运行：

```bash
VERSION=v0.1.0
curl -fsSL "https://github.com/hajimilvdou/qwq-panel/releases/download/${VERSION}/install.sh" -o install.sh
sudo bash install.sh --version "${VERSION}"
```

安装脚本会自动检测架构（`linux/amd64` / `linux/arm64`）、校验 `SHA256SUMS.sig` 签名，并在终端提供可选插件勾选菜单。也支持非交互参数：

```bash
# 仅安装极简底座 + security.basic
sudo bash install.sh --version "${VERSION}" --minimal

# 指定按需安装的插件（逗号分隔或 all）
sudo bash install.sh --version "${VERSION}" --plugins monitor.basic,web.ingress,notify.hub
```

安装完成后，按终端输出的一键初始化链接通过 SSH 隧道访问：

```bash
ssh -L 8443:127.0.0.1:8443 root@<你的服务器IP>
```

---

## 官方可选插件（按需下载）

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

每次发版均会同步发布 `plugins-index.json` 元数据索引与各架构 `.qwqpkg` 签名包，可通过 `qwqctl verify` 或宿主信任根（`/etc/qwq/trust/`）验签。

---

## 支持平台

目标平台：Debian 12+ / Ubuntu 22.04+ / Rocky·Alma 9+，要求 `systemd ≥ 249`、`cgroup v2`、内存 ≥ 1 GiB。

| 平台 | 验证状态 | 说明 |
|---|---|---|
| Ubuntu 24.04 | 已实测 | 推荐平台 |
| Ubuntu 22.04 | 未在真机完整验证 | polkit 0.105 不读 JS 规则，插件启停会受限，`qwq doctor` 会给出明确提示 |
| Debian 12 | 未在真机完整验证 | 最小化镜像通常未预装 `polkitd`，需先 `apt install polkitd` |
| Rocky 9 / Alma 9 | 未在真机完整验证 | SELinux enforcing 下需按 `qwq doctor` 提示核对文件标签 |

---

## 文档与开发

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — 系统架构说明
- [docs/adr/](docs/adr/) — 架构决策记录（ADR）
- [docs/operations/](docs/operations/) — 安装、发布、备份与运维手册（发布流程见 [docs/operations/release.md](docs/operations/release.md)）
- [api/qwq/platform/v1/platform.proto](api/qwq/platform/v1/platform.proto) — Platform ABI v1 协议定义
- [api/manifest/v1/manifest.schema.json](api/manifest/v1/manifest.schema.json) — 插件 Manifest 规范
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

## 许可证

本仓库按目录分区许可（详见 [NOTICE](NOTICE) 与 [CONTRIBUTING.md](CONTRIBUTING.md)）：

- `api/`、`sdk/`、`web/kit/`：**Apache-2.0**（插件仅依赖 `sdk/`，可采用任意许可证）
- 其余宿主、Web Shell 与内置插件：**AGPL-3.0-only**（同时提供商业授权）
