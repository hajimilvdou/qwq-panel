# qwq：模块化服务器运维面板

与阿里通义千问的 QwQ 模型无关。

当前阶段：全量核心能力、103 条公共 API 契约、随机高位端口 + 安全密道 + F12 级无服务伪装（反代域名自动关闭）及 6 大主流发行版适配均已就绪；首版交付单机（standalone）形态。

## 支持平台

目标平台（ADR-0005 Q4）：Debian 11+ / Ubuntu 22.04+ / Rocky·Alma 9+，systemd ≥ 247、cgroup v2、1 GiB 内存起。

- **原生支持系统（推荐，零补丁）**：**Ubuntu 24.04 / 26.04 LTS、Debian 12 / 13** —— 原生具备 `polkit >= 0.106`（支持 JS 规则），`install.sh` 保持 100% 原生部署，**不下载也不安装任何兼容补丁**。
- **旧版系统自动补丁支持（体验与原生一致）**：**Ubuntu 22.04 LTS、Debian 11** —— 系统自带旧版 `polkit 0.105` 或缺少 `polkitd`，`install.sh` 会自动检测并从 GitHub Releases 下载经 Ed25519 验签的独立补丁 `qwq-compat-polkit`（按需 socket 激活、零常驻内存、仅限 `qwq-plugin@*` 单元，权限边界与原生 polkit JS 规则严格等价）。

| 平台 | 验证状态 | 说明 |
|---|---|---|
| Ubuntu 24.04 LTS (amd64 / arm64) | ✅ 已实测（原生） | 主力推荐平台，GitHub Actions KVM 完整 E2E 全绿 |
| Ubuntu 26.04 LTS | ✅ 已实测（原生） | 内核 7.0 + `SO_PEERPIDFD` + `polkitd 127` + `systemd 259` 全绿 |
| Debian 12 (bookworm) | ✅ 已实测（原生） | `systemd 252` + `polkitd 122`，完整安装/沙箱/卸载全绿 |
| Debian 13 (trixie) | ✅ 已实测（原生） | `systemd 257` + `polkitd 126`，完整安装/沙箱/卸载全绿 |
| Ubuntu 22.04 LTS | ✅ 已实测（自动补丁） | `install.sh` 自动安装 `qwq-compat-polkit`，插件沙箱与原生一致 |
| Debian 11 (bullseye) | ✅ 已实测（自动补丁） | `systemd 247` + `install.sh` 自动安装 `qwq-compat-polkit`，插件沙箱与原生一致 |
| Rocky 9 / Alma 9 | **未验证** | SELinux enforcing 下 `/opt/qwq` 与插件树里的二进制可能因标签（非 `bin_t`）无法执行（203/EXEC）；doctor 报 `selinux` 警告并给出排查命令 |

许可证：宿主 AGPL-3.0-only + 商业授权；插件 SDK 与公共契约 Apache-2.0（ADR-0005，分区见 [NOTICE](NOTICE)，贡献规则见 [CONTRIBUTING.md](CONTRIBUTING.md)）。

**接手请先读 [`docs/HANDOFF-2026-11-01c.md`](docs/HANDOFF-2026-11-01c.md)，再读 [`IMPLEMENTATION-PLAN.md`](IMPLEMENTATION-PLAN.md) §0。**

| 文件 | 内容 |
|---|---|
| [IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md) | 施工计划：待确认决策、开发环境规则、任务与验收、验证命令 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 系统架构 v1.1 |
| [docs/adr/](docs/adr/) | 决策记录：0001 基线、0002 插件放置、0003 拉起与传输认证、0004 AI 原生操作面、0005 项目基线（名称、许可证、平台、TLS、身份、首版范围）、0006 公共 API 类型生成、0007 Platform ABI v1 冻结评审、0008 宿主内部结构、0009 首版插件与基础防护 |
| [docs/HANDOFF.md](docs/HANDOFF.md) | 项目背景、约束、风险、未决事项、术语 |
| [docs/ARCHITECTURE-REVIEW.md](docs/ARCHITECTURE-REVIEW.md) | 架构审查与落实情况 |
| [api/qwq/platform/v1/platform.proto](api/qwq/platform/v1/platform.proto) | Platform ABI v1（冻结评审见 ADR-0007）；节点协议草案在 `api/qwq/node/v1/` |
| [api/manifest/v1/manifest.schema.json](api/manifest/v1/manifest.schema.json) | 插件 manifest 规范，示例在 `examples/` |
| [tools/manifest_check.py](tools/manifest_check.py) | manifest 校验脚本（标准库，与 `sdk/manifest` 共用测试夹具） |
| [scripts/](scripts/) | `remote.sh`（构建机同步与执行）、`check.sh`（质量门禁）、`dev-env.sh`、`bootstrap-tools.sh`、`tools.lock` |
| [ui-design/DESIGN.md](ui-design/DESIGN.md) | UI 规范；原型在 `ui-design/prototype/index.html` |
| [archive/v1-baseline/](archive/v1-baseline/) | v1 原文，只读 |

工作规则：所有工具、缓存和配置都放在项目文件夹内，不污染本机环境；编译与测试在 Linux 构建机上进行（`IMPLEMENTATION-PLAN.md` §2）。
