# core.xray 供应链基线

> 移植说明：源自 WorkBuddy 工作树 `main-50f25f0b`（基线 ea0bb91）的 `docs/plugins/core-xray/SUPPLY-CHAIN.md`，2026-11-13 移植到本仓克隆 `.cache/wt/core-xray`（基于 main `ccbfb13`）。上游 Xray 证据表按原样保留（另一模型 2026-11-13 从官方来源锁定）；本地下载与哈希复算仍未执行，待 X0。源工作树只读，未改动。

- 记录日期：2026-11-13（源）；2026-11-13 移植刷新；2026-11-14 X0 下载/复算/隔离执行
- 基线分支：本仓 `fix/core-xray`（克隆 `.cache/wt/core-xray`，基于 main `ccbfb13`）；源证据采集于 `workbuddy/main-50f25f0b` @ `ea0bb91aa37ebc1a36e5acb61bab103533bdc4da`
- 状态：**X0 证据链已闭合**（tag→commit→发布包哈希→二进制哈希→隔离执行版本一致）；原生字段 UDS/预检/真实转发仍待 X6/X11

## 1. 选定上游

| 项 | 值 | 证据 |
|---|---|---|
| 项目 | XTLS/Xray-core | https://github.com/XTLS/Xray-core |
| 版本 | `v26.11.9` | https://github.com/XTLS/Xray-core/releases/tag/v26.11.9 |
| commit | `676eaf66f8f05d4d558ee7a74b4736623d3feeb9` | 同上 release 页 commit 链接 |
| 平台 | linux/amd64 | 首版目标 |
| 发布资产 | `Xray-linux-64.zip` | https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip |
| 官方摘要 | `Xray-linux-64.zip.dgst` | https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip.dgst |
| 官方 SHA2-256 | `b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82` | 上述 `.dgst` 文本 |
| 许可证 | MPL-2.0 | https://raw.githubusercontent.com/XTLS/Xray-core/v26.11.9/LICENSE |

发布页显示 commit 带 GitHub verified signature；这不能替代下载资产后的本地哈希复算。

## 2. 已执行的核验（X0，2026-11-14）

用户 2026-11-13 批准按锁定 v26.11.9 官方 release 下载与隔离 Linux 执行。核验材料存本克隆 `.cache/core-xray/v26.11.9/`（gitignore，不进 Git）；隔离执行在构建机 `/root/qwq-dev/core-xray/.cache/` 下，未启动任何业务监听。

| 步骤 | 命令 | 结果 |
|---|---|---|
| 官方摘要 | `curl -sSL …/Xray-linux-64.zip.dgst` | SHA2-256=`b651f7e1…95f82`（与 §1 一致） |
| 发布包复算（开发机） | `sha256sum Xray-linux-64.zip` | `b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82` ✅ 逐字匹配 |
| 发布包复算（构建机） | `sha256sum Xray-linux-64.zip` | 同上 ✅（官方/开发机/构建机三方一致） |
| 二进制复算 | `sha256sum unpacked/xray` | `e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d`（开发机=构建机） |
| 隔离执行版本 | `./unpacked/xray version` | `Xray 26.11.9 (Xray, Penetrates Everything.) 676eaf6 (go1.27.3 linux/amd64)` ✅ commit 短哈希 `676eaf6` 与 §1 一致 |
| 配置测试命令 | `./unpacked/xray help` | 含 `run`（默认，`run -test` 仅预检）、`version`、`api`、`x25519`（REALITY 密钥）、`uuid`（VLESS） |

解包文件清单（SBOM，来源均为官方 zip）：

| 文件 | 大小 | 说明 |
|---|---|---|
| `xray` | 35,434,620 B | 主二进制，sha256 见上 |
| `geoip.dat` | 2,950,563 B | GeoIP 数据（首版 direct 出站不用路由，可不含） |
| `geosite.dat` | 7,760,982 B | GeoSite 数据（同上） |
| `LICENSE` | 16,725 B | MPL-2.0 原文 |
| `README.md` | 12,750 B | 上游说明 |

证据链结论：tag `v26.11.9` → commit `676eaf66…` → 发布包 sha256 `b651f7e1…` → 二进制 sha256 `e87bce58…` → 执行版本 `26.11.9/676eaf6` 全链一致。**二进制与秘密均未进 Git**。原生字段 UDS 可行性、`run -test` 不监听、真实转发仍属 X6/X11 未决（§4），不在此宣称已支持。

## 3. 首版原生契约证据

| 主题 | 当前证据 | 施工约束 |
|---|---|---|
| VLESS 入站用户 | `infra/conf/vless.go` 的 `VLessInboundConfig` 同时有 `users` 与旧 `clients`；`clients != nil` 时映射到 users | 首版使用 `users`，不根据旧示例继续使用 `clients` |
| VLESS flow | 同文件仅接受 `vless.XRV` 或空默认；当前目标为 `xtls-rprx-vision` | 不支持其他 flow |
| VLESS decryption | 同文件要求显式有效值，禁用时为 `none` | 渲染固定 `decryption:"none"` |
| RAW/TCP | `TransportProtocol.Build` 将 `raw` 与旧 `tcp` 都映射为内部 `tcp` | Core Intent 固定 `raw`，渲染 `network:"raw"` |
| REALITY transport | 同文件只允许 `tcp`、`splithttp`、`grpc` | 首版仅 RAW/TCP |
| REALITY 字段 | 官方 REALITY 文档列出 `target`、`serverNames`、`privateKey`、`shortIds`；`dest` 为 target 的旧别名 | 首版使用 `target`，不使用旧 `dest` |
| shortIds | 官方文档允许 0–f 的偶数长度 hex，上限 16；空字符串表示允许无 short ID | 首版不接受空字符串，固定要求非空 hex |
| 用户统计 policy | `infra/conf/policy.go`：`statsUserUplink`、`statsUserDownlink` | level 0 开启二者 |
| 入站统计 policy | 同文件：`statsInboundUplink`、`statsInboundDownlink` | system 开启二者 |
| StatsService | `app/stats/command/command.proto` 提供 `GetStats`、`QueryStats`、`GetSysStats` 等；`reset` 字段存在 | 只读查询，永远 `reset=false` |
| Stats proto package | `xray.app.stats.command` | go_package `github.com/xtls/xray-core/app/stats/command` |
| 配置预检 | 官方命令文档：`xray run -test` 表示只测试配置、不启动 server | 仍需 X6 实测端口和进程行为 |
| API listen | `infra/conf/api.go` 只透传 `Listen` 字符串；官方文档展示 IP+端口 | UDS 仍未证实，X6 为硬门禁 |

原始证据链接：

- https://raw.githubusercontent.com/XTLS/Xray-core/v26.11.9/infra/conf/vless.go
- https://raw.githubusercontent.com/XTLS/Xray-core/v26.11.9/infra/conf/transport_internet.go
- https://xtls.github.io/en/config/transports/reality.html
- https://raw.githubusercontent.com/XTLS/Xray-core/v26.11.9/infra/conf/policy.go
- https://raw.githubusercontent.com/XTLS/Xray-core/v26.11.9/app/stats/command/command.proto
- https://raw.githubusercontent.com/XTLS/Xray-core/v26.11.9/infra/conf/api.go
- https://xtls.github.io/en/document/command

## 4. 未决问题

- 文件系统 UDS 上 StatsService 的配置形式、socket 权限和其他 UID 拒绝行为。
- 锁定版本 `run -test` 是否在 Reality 等所有相关初始化路径都绝不监听。
- 最小 StatsService proto 的依赖闭包与生成方式。
- 真实 VLESS/REALITY/Vision/RAW 客户端连接和计数器增长。
- 同 systemd 单元内驱动/Xray 的进程回收和资源实测。

以上均需 X6/X11 证据，不能提前写为已支持。