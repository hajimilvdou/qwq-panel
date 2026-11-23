<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# `qwq` 自定义插件制作、打包、签名与安装规范

本规范面向希望为 `qwq` 面板开发、签名并分发自定义插件（`.qwqpkg`）的开发者，覆盖 **Manifest 1.3 结构**、**Go `sdk/pluginsdk` 后端规范**、**零内联 CSP + `@qwq/kit` v2 前端桥接协议**、**`qwq plugin` 开发者 CLI 四步命令流**，以及 **Web 面板 `/apps/install` 动态信任公钥与远程 HTTPS 拉取安装流程**。

---

## 1. 插件目录结构与 `manifest.json` 1.3 全解

### 1.1 标准源码与打包目录结构

一个合规的 `qwq` 插件源码目录如下（可通过 `qwq plugin init` 一键生成）：

```text
acme.hello/
├── manifest.json                 # 插件元数据、能力声明、操作面与文件摘要（核心签名对象）
├── main.go                       # 基于 sdk/pluginsdk 的 Go 入口
├── bin/
│   └── plugin                    # 目标架构 Linux 静态编译产物（manifest.entrypoint）
├── schemas/
│   ├── config.schema.json        # 插件配置 JSON Schema（必须位于此固定路径）
│   ├── hello.request.json        # 操作入参 JSON Schema 2020-12
│   └── hello.response.json       # 操作出参 JSON Schema 2020-12
├── attestations/
│   └── sbom.spdx.json            # SPDX SBOM 声明（manifest.provenance.sbom）
├── ui/                           # 可选：前端沙箱 UI 静态资源（零内联 CSP）
│   ├── index.html
│   ├── plugin.css
│   └── plugin.js
└── README.md
```

> **容器格式说明**：`.qwqpkg` 是规范化的 `tar.gz` 归档。首条文件必为 `manifest.json`，第二条必为 Ed25519 分离签名 `signatures/manifest.sig`（对 `manifest.json` 原始字节签名），其余文件严格按 `manifest.files` 逐一核对 `sha256:` 摘要，不允许符号链接、绝对路径或路径穿越。

### 1.2 `manifest.json`（`schema_version: "1.3"`）核心字段全解

| 字段 | 必填 | 约束与说明 |
| :--- | :--- | :--- |
| `schema_version` | 是 | 固定 `"1.3"`（支持 `ui.widgets`、权限命名空间校验与 `reachability` 失联风险标注）。 |
| `id` | 是 | 匹配 `^[a-z][a-z0-9]*([.-][a-z0-9]+)*$`，建议 `<vendor>.<name>`（如 `acme.hello`）；禁止使用宿主保留前缀 `host` / `qwq`。 |
| `version` | 是 | 标准 SemVer（如 `"0.1.0"`）。版本目录不可变，升级必须递增版本号。 |
| `name` / `summary` / `description` | 是 / 是 / 否 | 单行名称（≤64）、单行简介（≤120）、多行说明（≤2000），禁止控制字符与双向覆盖字符。 |
| `publisher` | 是 | `{"id": "<lowercase-slug>", "key_id": "ed25519:<64位小写hex>"}`；`key_id` 为 32 字节 Ed25519 原始公钥的 SHA-256。 |
| `abi` / `engine_constraint` | 是 | `{"major": 1, "minimum_minor": 0}` 与宿主版本范围（如 `">=0.1.0 <1.0.0"`）。 |
| `target` | 是 | `linux/amd64`、`linux/arm64`、`linux/riscv64`、`linux/arm/v6`、`linux/arm/v7` 之一。 |
| `entrypoint` | 是 | 必须以 `bin/` 开头（如 `"bin/plugin"`），且必须在 `files` 中列出；宿主启动前会由 `ExecStartPre` 复核其 SHA-256。 |
| `files` | 是 | 除 `manifest.json` 与 `signatures/*` 之外**所有包内文件**到 `"sha256:<64hex>"` 的映射；由 `qwq plugin pack` 自动计算并写回。 |
| `provenance.sbom` | 是 | 必须指向 `attestations/` 下的文件并在 `files` 中登记。 |
| `placement` | 是 | `"node"`（运行于受管节点）或 `"controller"`（运行于控制面）。 |
| `lifecycle` | 是 | `startup`（`on_demand` / `eager`）、`background`（`true` 时必须 `eager`）、`update_strategy`（`restart` / `auto` / `blue_green`）、`overlap_safe`。1C1G 低资源推荐 `on_demand` + `restart` + `overlap_safe: false`。 |
| `capabilities` | 是 | 顶层能力白名单数组：`[{"name": "state.kv.read", "scope": "self", "reason": "..."}]`。宿主持久依据已签名能力推导 systemd 沙箱放宽（如 `network.egress` / `network.listen` / `network.proxy:direct`），高敏能力在安装向导需用户逐项勾选确认。 |
| `operations` | 是 | 插件对外操作面，每项需声明 `name`、`api_version`（`v1`）、`permission`（**必须以 `<plugin_id>:` 开头**，且写/破坏性操作不可使用只读动作 `read/list/get/export/describe/watch`）、`mode`（`invoke`/`job`）、`effect`（`read`/`write`/`destructive`）、`risk`（`low`/`medium`/`high`）、`idempotent`、`timeout_ms`（1–300000）、`request_schema`、`response_schema`。`approval` 可选 `auto` / `ai_confirm` / `confirm`（后两者必填 `approval_summary`）；可能切断 SSH/面板连通性的高危写操作应声明 `reachability: true`。 |
| `resources` | 是 | 硬性 cgroup 资源预算：`memory_max_mb`（≥16）、`cpu_quota_percent`（≥1）、`pids_max`（≥1）、`fds_max`（≥16）、`disk_max_mb`（≥1）、`kv_max_kb`（默认 4096）。 |
| `state` / `config` | 是 | `state` 声明 `schema_version`、`minimum_rollback_version`、`backup_paths`（非空时宿主通过 `StateDirectory=` 自动分配持久 `data_dir`）；`config` 固定 `schema: "schemas/config.schema.json"` 与 `hot_apply`。 |
| `ui` | 否 | `entry`（须以 `ui/` 开头）、`sandbox: true`、`kit_major: 1`、`connect_sources`（外连 HTTPS 源白名单，默认 `[]`）、`routes`（侧栏与路由权限须以 `<plugin_id>:` 开头）、`widgets`（概览页声明式卡片：`stat` / `series` / `checks` / `list`，必须绑定 `effect=read` + `mode=invoke` 操作）。 |

---

## 2. 后端 `sdk/pluginsdk` 最小代码规范

### 2.1 SPDX 许可与模块边界

- 外部独立插件推荐使用 `// SPDX-License-Identifier: Apache-2.0`（与 `sdk/` 同源，Apache-2.0 友好）；合入宿主仓库的内置插件须遵守仓库 AGPL-3.0 协议头 `// SPDX-License-Identifier: AGPL-3.0-only`。
- 插件**只允许依赖 `github.com/qwq-panel/qwq/sdk/...`** 与标准库/第三方公开包，严禁引用宿主 `internal/...`。

### 2.2 最小 `Invoke` / `RunJob` / `ServePublicRoute` 实现

```go
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

//go:embed manifest.json
var manifestJSON []byte

type myPlugin struct{}
type myInstance struct{ *pluginsdk.InstanceBase }

func (p *myPlugin) NewInstance(_ context.Context, info pluginsdk.InstanceInfo) (pluginsdk.Instance, error) {
	inst := &myInstance{InstanceBase: pluginsdk.NewInstanceBase(info)}

	// 1. 同步操作（mode: "invoke"）
	inst.HandleInvoke("hello", func(ctx context.Context, req pluginsdk.Request) (pluginsdk.Response, error) {
		body, _ := json.Marshal(map[string]string{"message": "hello from qwq plugin"})
		return pluginsdk.Response{Payload: body}, nil
	})

	// 2. 长任务操作（mode: "job"）
	// inst.HandleJob("sync", func(ctx context.Context, req pluginsdk.Request, progress pluginsdk.Progress) (pluginsdk.Result, error) {
	//     _ = progress(pluginsdk.ProgressUpdate{Percent: 50, Message: "synchronizing..."})
	//     return pluginsdk.Result{Payload: []byte(`{"ok":true}`)}, nil
	// })

	return inst, nil
}

// 3. 可选：对外公开 HTTP 路由（宿主网关代理 /p/<plugin_id>/* 或绑定自定义域名）
// func (i *myInstance) ServePublicRoute(ctx context.Context, req pluginsdk.PublicRouteRequest) (pluginsdk.PublicRouteResponse, error) {
//     return pluginsdk.PublicRouteResponse{
//         Status:  200,
//         Headers: []pluginsdk.HTTPHeader{{Name: "content-type", Value: "text/plain; charset=utf-8"}},
//         Body:    []byte("ok"),
//     }, nil
// }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := pluginsdk.ServeSystemd(ctx,
		pluginsdk.SystemdOptions{PluginID: os.Getenv(pluginsdk.EnvPluginID)},
		pluginsdk.Options{Plugin: &myPlugin{}, Manifest: manifestJSON},
	); err != nil {
		fmt.Fprintln(os.Stderr, "acme.hello:", err)
		os.Exit(1)
	}
}
```

### 2.3 1C1G 低资源内存红线与按需休眠

- 宿主会通过 systemd cgroup `MemoryMax=` 与 `GOMEMLIMIT` 严格约束插件内存。建议常规工具类插件 `memory_max_mb` 设为 `24–48 MB`，编译时附加 `-trimpath -ldflags="-s -w"` 减小二进制体积。
- 若 `lifecycle.startup` 设为 `"on_demand"` 且 `background: false`，`sdk/pluginsdk` 会自动读取 `QWQ_PLUGIN_IDLE_TTL` 启用空闲优雅休眠（scale-to-zero），降低闲置 VPS 内存占用。

---

## 3. 前端零内联 CSP 规范与 `@qwq/kit` v2 桥接协议

### 3.1 零内联 CSP 硬红线

插件 UI 运行在受限 `<iframe sandbox="allow-scripts allow-forms allow-downloads">` 中，且宿主在安装暂存期（`checkUIAssets`）与静态服务响应头都会强制执行严格 CSP：

1. **严禁内联脚本与事件属性**：禁止 `<script>...</script>` 内联代码块、禁止 `onclick="..."` 等内联事件处理器，所有逻辑必须外置为同包 `./plugin.js`。
2. **严禁内联样式**：禁止 `<style>...</style>` 块与内联 `style="..."` 属性，所有样式必须外置为同包 `./plugin.css`。
3. **严禁运行时外链脚本**：禁止 `<script src="https://...">`、`import('https://...')`、`importScripts('https://...')`、`new Worker('https://...')`；安装包检验会直接以 `UI_REMOTE_SCRIPT` 拒绝。
4. **不可信文本防 XSS**：渲染后端/日志数据时优先使用 `textContent`、`document.createElement`，禁止拼装 `innerHTML`。

### 3.2 `@qwq/kit` v2 `MessageChannel` 握手与受控能力

插件页面无需引用 Web Shell，直接通过 `postMessage` 建立隔离 `MessagePort`：

1. **握手**：页面加载后向 `window.parent.postMessage({ t: 'plugin.hello', kit_major: 1 }, '*')`。
2. **接管端口**：监听 `window` 的 `message` 事件，校验 `event.source === window.parent && event.data?.t === 'plugin.port'` 后保存 `event.ports[0]`，发送 `{ t: 'ui.ready' }` 通知宿主撤下骨架屏，并通过 `ResizeObserver` 发送 `{ t: 'ui.resize', height }`。
3. **主题与公开访问源同步**：监听端口上的 `{ t: 'ui.settings', theme, motion, density, tokens, public_origin }`：
   - 将 `document.documentElement.dataset.theme` 同步为 `'light'` 或 `'dark'`；
   - 生成面向外部用户的公开链接时，应基于 `settings.public_origin`（如探针状态页 / 订阅链接）而非 `location.origin`（沙箱 iframe 的 `location.origin` 为不透明 `null`）。
4. **宿主受控确认框（`ui.confirm`）与剪贴板（`ui.copy`）**：
   - 发送 `{ t: 'ui.confirm', id, title, body, danger, confirm_label }` -> 等待 `{ t: 'ui.confirm.result', id, ok, data: { confirmed } }`；
   - 发送 `{ t: 'ui.copy', id, text, label }` -> 等待 `{ t: 'ui.copy.result', id, ok }`（解决沙箱 iframe 无法直接访问 `navigator.clipboard` 的限制）。
5. **三态审批解包（`api.invoke` -> `api.result`）**：
   - 发送 `{ t: 'api.invoke', id, operation, payload }` 后，收到的 `api.result` 在 `ok === true` 时，`data` 可能是标准 Operation 信封，需要按三态解包（与 `@qwq/kit` 的 `unwrapInvokeOutcome` 一致）：
     - **`done`**：`status === 'SUCCEEDED'`（或无 `status`），业务数据位于 `data.result ?? data`；
     - **`running`**：`status === 'RUNNING' | 'PENDING'`，记录 `operation_id` 提示进行中；
     - **`awaiting_approval`**：`status === 'AWAITING_APPROVAL'` 或存在 `approval_id`，此时绝不是报错——应提示用户“已提交，请在宿主审批浮窗确认”并等待审批完成；
     - 若 `status` 为 `FAILED` / `REJECTED` / `CANCELED` / `EXPIRED` 或存在 `data.error`，按错误展示 `error.detail || error.message`。
6. **页面卸载清理**：监听 `pagehide`，断开 `ResizeObserver`、清理所有 `pending` 定时器并调用 `port.close()`。

---

## 4. `qwq plugin` 开发者 CLI 四步命令流

`qwq` 主二进制内置完整的插件开发与发布子命令，所有加密格式均与官方发布工具链（`sdk/manifest` + `sdk/pkgfile`）完全一致。

### 第一步：在插件源码目录**之外**生成 Ed25519 发布者密钥对（`keygen`）

```bash
qwq plugin keygen --out-priv ./publisher.key.pem --out-pub ./publisher.pub.pem
```

- **切勿将私钥放入插件源码目录内**（例如 `./acme-hello/`）：`qwq plugin pack` 会拒绝打包源码目录中的 `.pem`/`.key` 文件或任何包含 `-----BEGIN ... PRIVATE KEY-----` 的文件。
- `publisher.key.pem`：PKCS#8 PEM 私钥，权限强制 `0600`（严禁提交至 Git 或泄露）。
- `publisher.pub.pem`：PKIX PEM 公钥，权限 `0644`（分发给用户导入面板信任根）。
- 命令拒绝覆盖已存在密钥文件，并在标准输出打印规范 `key_id`（形如 `ed25519:<64位小写hex>`）。

### 第二步：初始化插件骨架（`init`）

```bash
qwq plugin init ./acme-hello \
  --id acme.hello \
  --name "Acme Hello" \
  --with-ui
```

- 自动生成符合 Manifest 1.3 规范的 `manifest.json`、`main.go`、`schemas/*.json`、`attestations/sbom.spdx.json`、零内联 CSP + `@qwq/kit` v2 握手的 `ui/{index.html,plugin.css,plugin.js}` 与 `README.md`。
- 若不需要前端页面，可传 `--with-ui=false`。

### 第三步：初始化 Go 模块、交叉编译并打包签名（`pack`）

先初始化独立 `go.mod` 并拉取 `sdk`，再针对目标服务器架构静态编译 Linux 二进制（直接输出至 `./bin/plugin` 或源码目录之外）：

```bash
cd ./acme-hello
go mod init acme.hello
go get github.com/qwq-panel/qwq/sdk
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ./bin/plugin .
cd ..
```

执行打包与 Ed25519 签名（若二进制输出在源码目录外，可通过 `--entrypoint ../build/plugin` 注入到 `bin/plugin`）：

```bash
qwq plugin pack ./acme-hello \
  --out ./dist/acme.hello-0.1.0.qwqpkg \
  --key ./publisher.key.pem
```

- 自动排除 `.git`、`signatures/`、`*.qwqpkg` 以及 `--key` / `--out` / `--entrypoint` 所指向的同文件，并硬拒绝源码目录中任何 `.pem`/`.key` 或私钥内容文件；
- 严格校验 `manifest.entrypoint` 必须位于 `bin/` 之下（拒绝绝对路径、`..` 与路径穿越），并通过 `--entrypoint` 自动赋予可执行位；
- 若 `manifest.json` 中的 `publisher.key_id` 仍为占位全零值，自动填充为当前签名私钥对应的 `key_id`；
- 计算全部文件的 `sha256:` 摘要、严格执行 `sdk/manifest` 语义校验并写入确定性签名包。

### 第四步：离线验签与完整性校验（`verify`）

```bash
# 指定单个公钥文件
qwq plugin verify ./dist/acme.hello-0.1.0.qwqpkg --trust ./publisher.pub.pem

# 或指定包含多个 *.pem 的信任目录
qwq plugin verify ./dist/acme.hello-0.1.0.qwqpkg --trust /etc/qwq/trust
```

- 离线复核容器边界、Ed25519 签名、Manifest 1.3 规则与每一个文件摘要；
- 输出 `id`、`version`、`publisher`、`key_id`、`files`、`capabilities` 与 `verified: OK`。任一字节被篡改或公钥不匹配均会返回非零退出码。

---

## 5. 在面板 `/apps/install` 导入公钥并安装

`qwq-controller` 运行时采用动态复合信任根（`CompositeTrustStore`）：
- **官方系统公钥**（`source: "official"`）：读取自只读目录 `/etc/qwq/trust/*.pem`，面板界面只读展示、禁止删除；
- **自定义开发者公钥**（`source: "custom"`）：持久化于 `<DataDir>/trust/publishers/`，管理员在 Web UI 添加或删除后**立即生效，无需重启 `qwq-controller`**。

### 5.1 导入第三方开发者信任公钥

1. 打开面板 **「应用中心 → 安装应用」（`/apps/install`）**，点击右上角 **「开发者信任公钥」** 按钮（或当安装包在检查步因未信任公钥被拦截时，直接点击卡片内的 **「导入开发者信任公钥」**）。
2. 填写开发者 / 组织标签，粘贴开发者公开的 `publisher.pub.pem`（`-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----`）。
3. 若当前管理员账号开启了 TOTP 二步验证且会话未处于新鲜 MFA 状态，界面会自动弹出二步验证码输入框，通过 `X-QWQ-MFA-Code` 完成复核并写入宿主机审计日志。
4. 添加成功后，缓存的安装包检查结果会立即失效并自动重新检查，签名状态立刻转为 **有效且受信任**。

### 5.2 两种安装方式

在 `/apps/install` 第一步可自由切换来源：

1. **方式 A：拖拽 / 上传本地 `.qwqpkg`**
   - 将签名后的 `.qwqpkg`（≤ 64 MiB）拖入上传区或点击选择文件，实时显示上传进度并自动进入安装前检查（签名 / 兼容性 / 内存 / 磁盘）。
2. **方式 B：从 HTTPS / GitHub Release URL 一键拉取**
   - 切换至 **「从 HTTPS / GitHub URL 拉取」**，填入公开的 `https://` 直链（例如 `https://github.com/<org>/<repo>/releases/download/v0.1.0/acme.hello-0.1.0.qwqpkg`），可选填写发布页提供的 64 位 SHA-256 校验和。
   - 服务端拉取器内置严格防 SSRF 保护：仅允许 `https://`，拒绝内嵌凭据、回环地址（`127.0.0.0/8`、`::1`、`localhost`）、RFC1918/RFC4193 私有网段、链路本地与云元数据（`169.254.0.0/16`、`fe80::/10`）、CGNAT（`100.64.0.0/10`）及多播/未指定地址，并在重定向每一跳防 DNS 重绑定；传输上限 64 MiB、超时 60 秒，下载完成后直接进入与本地上传完全一致的暂存与验签安装流程。
3. 通过检查步后，在 **「授权」** 步骤核对并勾选所需能力（高敏能力须逐项手动确认），点击 **「同意并安装」** 即可完成沙箱部署与启动。
