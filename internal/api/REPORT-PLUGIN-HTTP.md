# P3-T4：插件 HTTP 安装 / 更新 / 回滚 / 配置 / 列表端点

SPDX-License-Identifier: AGPL-3.0-only

状态：完成（HTTP 层 + 真实 updater adapter）。未做 UI、未做卸载（updater 尚无 Uninstall API）。

## 1. 交付文件

| 文件 | 内容 |
|---|---|
| `internal/api/plugin_types.go` | `PluginManager` 接口 + API 内部 DTO（`Plugin`、`PluginVersion`、`PluginUpdate`、`PluginConfig`、请求类型） |
| `internal/api/plugin_uploads.go` | 上传暂存：multipart 只取 `package`、0600 随机文件、`upl_` 随机 id、15 分钟过期、启动清理、并发上限 |
| `internal/api/plugins.go` | 上传/安装/更新/回滚/列表/详情/配置 handler、幂等重放、config secret 提取与脱敏 |
| `internal/api/plugins_test.go` | fake `PluginManager` + 真实网关/控制器/上传目录的 handler 测试 |
| `cmd/qwq/plugin_manager.go` | `api.PluginManager` 的 updater adapter；配置 schema 从不可变版本目录读取并做路径约束 |
| `cmd/qwq/plugin_manager_test.go` | adapter 参数映射、restart 强制、回滚 revision 预检、config schema 路径穿越测试 |
| `internal/gateway/{gateway.go,routes.go,middleware.go}` | 新增 `BodyPackage`（multipart）与 `max_package_bytes`（64 MiB） |
| `internal/pluginhost/updater/options.go` | 只增只读查询 `AllVersions()`（`listVersions(ctx, "")` 的导出包装） |
| `api/public/v1/openapi.yaml` | 新增 5 条操作、8 个 schema，改写 `Plugin` / `PluginInstallRequest` / `PluginList` 契约 |
| `tools/vacuum/ruleset.mjs` | `max_package_bytes` 加入 limits 白名单；`qwq-request-closed` 允许唯一一处 multipart 上传 |
| `internal/catalog/host_gen.go` | `go generate ./internal/catalog` 重新生成（见 §7 的 host action 说明） |
| `internal/api/{api.go,doc.go,dto.go,helpers_test.go}` | `Deps.Plugins` / `Deps.PluginUploads`、路由、测试注入 |
| `cmd/qwq/serve.go` | 用 `c.Updater()` 构造 adapter，`registerPublicRoutes` 接收可选 manager/upload store |

未改动：`go.mod`/`go.sum`、`sdk/`、updater 现有语义（只新增只读 `AllVersions`）、`internal/pluginhost/supervisor`、`cmd/qwq-privileged`、`deployments/`、`tests/e2e`。

## 2. 端点

所有端点沿用网关的认证、CSRF、Origin/Host、body limit 与 Problem 渲染。错误一律是
`application/problem+json`，权限经 `host.plugins:*` RBAC。

| Method | Path | 权限 | 幂等 | 成功响应 |
|---|---|---|---|---|
| POST | `/api/v1/plugin-packages` | `host.plugins:install` | exempt | `201 PluginPackageUpload` |
| POST | `/api/v1/plugins` | `host.plugins:install` | required | `201 PluginVersion` + `Location` |
| POST | `/api/v1/plugins/{plugin_id}/update` | `host.plugins:update` | required | `200 PluginUpdateResult` |
| POST | `/api/v1/plugins/{plugin_id}/rollback` | `host.plugins:rollback` | required | `200 PluginUpdateResult` |
| GET | `/api/v1/plugins` | `host.plugins:read` | — | `200 PluginList`（空时 `items: []`） |
| GET | `/api/v1/plugins/{plugin_id}` | `host.plugins:read` | — | `200 Plugin` / `404 NOT_FOUND` |
| GET | `/api/v1/plugins/{plugin_id}/config` | `host.plugins:read` | — | `200 PluginConfig`（脱敏） |
| PUT | `/api/v1/plugins/{plugin_id}/config` | `host.plugins:config` | required | `200 PluginConfig`（脱敏） |
| DELETE | `/api/v1/plugins/{plugin_id}` | `host.plugins:uninstall` | required | 未实现：`404 NOT_FOUND` |

无 updater 时：

- 上传、安装、更新、回滚、PUT config → `503 PLUGIN_UNAVAILABLE`；
- `GET /plugins` → `200` 空列表（保持旧行为，现有测试不炸）；
- `GET /plugins/{id}` / config GET → `404 NOT_FOUND`。

### 2.1 上传

```http
POST /api/v1/plugin-packages
Content-Type: multipart/form-data; boundary=...
（会话 + X-CSRF-Token，或 service account）

--boundary
Content-Disposition: form-data; name="package"; filename="任意名字"
<package bytes>
--boundary--
```

```json
201 Created
{
  "upload_id": "upl_0123456789abcdef0123456789abcdef",
  "size": 12345,
  "sha256": "…64 hex…",
  "expires_at": "2026-11-02T10:25:00.000Z"
}
```

- 只读取字段名 `package` 的字节；`filename` 与其它字段被忽略。
- 整个 multipart 请求体 ≤ `max_package_bytes`（64 MiB）；文件超过限制在流式写入时即 `413`。
- 上传不解析、不验签、不执行包；签名与 manifest 只在安装/更新时由 updater 校验。

### 2.2 安装

```json
POST /api/v1/plugins
{
  "upload_id": "upl_…",
  "accepted_capabilities": [{"name": "net.connect", "scope": "example.com"}],
  "expected_revision": "0"
}
```

```json
201 Created
Location: /api/v1/plugins/com.example.monitor
{
  "plugin_id": "com.example.monitor",
  "version": "1.2.3",
  "digest": "sha256:…",
  "status": "ACTIVE",
  "install_status": "INSTALLED",
  "active": true,
  "installed_at": "…",
  "activated_at": "…",
  "revision": "42"
}
```

- 插件 id 与版本来自签名 manifest；请求里没有 `version`/`plugin_id`（多传会被严格 JSON 解码拒绝）。
- `accepted_capabilities` 必须覆盖 manifest 声明的全部能力；`updater.checkCapabilities` 拒绝未知名称与未接受的新增能力。
- 成功后删除暂存文件；失败保留，允许用同一 `upload_id` 重试（测试覆盖）。

### 2.3 更新 / 回滚

更新请求与安装相同（`upload_id` + `accepted_capabilities` + 可选 `expected_revision`），路径里的
`plugin_id` 必须与 manifest 一致。生产 unit 是每插件一个，因此 adapter 通过
`Controller.UpdatePlugin` 强制 `updater.StrategyRestart`。

回滚 body 可省略：

```json
{"expected_revision": "42"}
```

`updater.Rollback` 没有 revision 参数，adapter 在调用前比较 active version revision；不匹配返回
`409 REVISION_CONFLICT` 与 `current_revision`。这是预检，不是与回滚同一事务的原子比较；updater 的
每插件锁仍串行化实际回滚。

成功响应：

```json
{
  "saga_id": "sag_…",
  "plugin_id": "com.example.monitor",
  "from_version": "1.0.0",
  "to_version": "1.1.0",
  "strategy": "restart",
  "state": "COMMITTED",
  "restarted": true,
  "version": { …PluginVersion… }
}
```

### 2.4 列表 / 详情

- `GET /plugins` 从 `updater.AllVersions()`（只读）按 plugin 聚合；每个插件返回 active 版本、
  `versions`（新到旧）、`active_status`、`install_status`、`config_revision` 与 manifest 摘要
  （`name`/`summary`/`publisher_id`/`placement`）。不返回完整 manifest、能力、路径或 secret。
- 分页使用 `limit`/`cursor`，cursor 是 opaque 的 plugin id；`since_revision` 被接受但当前返回完整快照
  （`delta=false`），与 `listUsers` 的现状一致。
- `fields` 投影与既有列表一致。
- 详情在无版本行时 `404`；有 rejected/staged 版本但没有 active 版本时仍返回该插件，
  `active_version`/`active_status`/`install_status` 省略。

### 2.5 配置

`GET /plugins/{id}/config` 返回 active revision；无配置时 `revision: "0"`、`config: {}`、`active: false`。

`PUT /plugins/{id}/config`：

```json
{"config": {"password": "plain", "url": "https://x"}, "expected_revision": "0"}
```

处理顺序：

1. 从 active version 的不可变目录读取 manifest 指定的 config schema；
2. `secrets.ExtractSecrets` 把 schema 标记为 `writeOnly: true` / `x-secret: true` 的值写入
   secret store（owner `plugins/<id>`、purpose `plugin.config`），配置文档中只留下 `{"$secret":"sec_…"}`；
3. `updater.ApplyConfig` 校验 + 应用 + 切换 active revision；
4. 响应与 GET 都通过 `secrets.RedactForExport` 把敏感值替换为 `[REDACTED]`。

`Secrets` 未配置或 schema 不可读时返回 `503 PLUGIN_UNAVAILABLE`，不会把明文存进 updater。
注意：客户端对敏感字段应发送明文；已有 `$secret` 引用会被 `ExtractSecrets` 当作普通值再加密一次
（现有 secrets 包语义，本任务未改）。

## 3. 上传生命周期与安全

```
上传请求 ──stream──▶ <StagingRoot>/upload-XXXXXX.pkg (0600)
   │                      │
   │                      ├─ sha256 / size 计算
   │                      ├─ 内存索引 {id → path,size,sha256,expires}
   │                      └─ id = "upl_" + 128 bit hex（与路径无关）
   ▼
install/update: 查 id → path → updater.Stage/Install
   ├─ 成功：删除文件 + 删除索引
   ├─ 失败：保留（可重试）
   └─ 15 分钟过期：Resolve/Sweep 删除文件 + 索引
```

- `upload_id` 先经 `^upl_[0-9a-f]{32}$` 校验，再查内存 map；请求永远不能提供本地路径。
- 暂存文件由 `os.CreateTemp` 生成随机名并以 0600 打开；multipart filename 不参与任何路径。
- `StagingRoot` 必须绝对路径；目录以 0700 创建。启动时删除遗留的 `upload-*.pkg`（id 只存在内存，
  旧进程的文件永远不可解析）。
- 最多 32 个待安装上传，超过返回 `503 UNAVAILABLE`；每次 Receive/Resolve/Sweep 惰性清理过期项。
- 删除前检查目标必须是暂存目录的直接子项，避免任何路径逃逸。
- 错误响应只包含 Problem 字段，不包含路径、文件名或 token；内部错误只进日志。

## 4. adapter 与接线

`cmd/qwq/serve.go`：

```go
if up != nil {
    pluginAPI = newPluginManager(c, *pluginsDir, logger)
    uploads, err = api.NewPluginUploads(filepath.Clean(*stagingDir),
        api.DefaultPluginUploadTTL, c.Clock())
}
routes, err := registerPublicRoutes(c, pluginAPI, uploads, logger)
```

- `newPluginManager` 持有 `*updater.Updater`、`Controller.UpdatePlugin`（强制 restart）与
  `pluginsRoot`；updater 为 nil 时返回 nil。
- `List`/`Get` 用 `AllVersions`/`Versions`/`Active`/`ActiveConfig`；`Install`/`ApplyConfig` 直传；
  `Update` 走 `Controller.UpdatePlugin`；`Rollback` 先做 expected revision 预检。
- `ConfigSchema` 只读 active version 的 `<pluginsRoot>/<id>/<version>/<manifest.config.schema>`：
  `sandbox.ValidateID` + 版本正则 + `filepath.Rel` 双重约束，读取上限 1 MiB，必须是合法 JSON。
- 上传目录初始化失败只禁用包路由并记录日志，列表/详情/operation 仍可用。

`internal/pluginhost/updater` 只新增一个只读方法：

```go
// AllVersions returns every recorded version of every plugin…
func (u *Updater) AllVersions() ([]Version, error)
```

未改变 `Install`/`Update`/`Rollback`/`ApplyConfig` 的语义或签名。

## 5. OpenAPI / 契约

- `POST /api/v1/plugins` 改为同步 `201 PluginVersion`；`PluginInstallRequest` 改为
  `{upload_id, accepted_capabilities, expected_revision?}`。
- 新增 `/api/v1/plugin-packages`、`/plugins/{plugin_id}/update`、`/plugins/{plugin_id}/rollback`、
  `/plugins/{plugin_id}/config`（GET/PUT）。
- 新增 schema：`PluginVersion`、`PluginPackageUploadRequest`、`PluginPackageUpload`、
  `PluginUpdateRequest`、`PluginRollbackRequest`、`PluginUpdateResult`、`PluginConfig`、
  `PluginConfigRequest`；重写 `Plugin`（版本列表 + active/status/config revision），移除不再使用的
  `PluginInstallation`/`PluginInstance`。
- 所有变更路由都有 `x-qwq-idempotency`（required 或 exempt+reason）与
  `x-qwq-action-exempt`（required 路由），或保留既有 `x-qwq-action`（DELETE uninstall）。
- 根 `x-qwq-limits` 新增 `max_package_bytes: 67108864`；上传操作也声明同一 override。
- `internal/api/contract_test.go` 的 `len(registered) == len(spec)-7` 断言自动同步：新增 5 条后
  仍成立；`cmd/qwq/serve_test.go` 路由数 52 → 57。
- `go generate ./internal/catalog` 幂等（重复执行 sha256 不变）。

## 6. 测试与检查

构建机（`QWQ_REMOTE_SRC=http1`，Linux，`CGO_ENABLED=1`）：

```
gofmt -l internal/api internal/gateway internal/pluginhost/updater internal/catalog cmd/qwq
  → 无输出

go vet ./internal/api/... ./internal/gateway/... ./internal/pluginhost/updater/... \
       ./internal/catalog/... ./cmd/qwq/...
  → 通过

staticcheck ./internal/api/... ./internal/gateway/... ./internal/pluginhost/updater/... \
             ./internal/catalog/... ./cmd/qwq/...
  → 通过（2026.2.2）

CGO_ENABLED=1 go test -race ./internal/api/... ./internal/gateway/... \
  ./internal/controller/... ./internal/pluginhost/updater/... \
  ./internal/catalog/... ./cmd/qwq/...
  → 全部 ok（api ≈14s，updater ≈30s，controller ≈11s，gateway ≈10s，cmd/qwq ≈3.5s）

go test ./internal/agentapi/... ./internal/catalog/... ./plugins/builtin/noop/...
  → 全部 ok

vacuum lint --no-update-check -b -q -d -n info -r tools/vacuum/ruleset.mjs \
  api/public/v1/openapi.yaml
  → Quality Score 100/100，0 error / 0 warning
```

新增 handler 测试覆盖：

- 上传：201 字段、0600 权限、忽略 filename、sha256、文件内容、404 过期/已消费、413（route limit）、
  415、坏 multipart、缺字段、空文件、重复 `package` 字段、路径穿越 `upload_id`；
- 安装：参数映射（path/capabilities/revision）、`Location`、版本来自 manager 而非请求、未知字段拒绝、
  失败保留上传并可重试、成功后删除、幂等重放、同 key 不同 body → `IDEMPOTENCY_KEY_REUSED`；
- 更新/回滚：manager 调用参数、更新强制 restart（adapter 测试）、rollback expected revision、409；
- 配置：secret 提取后 updater 只看到 `$secret`、响应脱敏、revision 0 空配置、404/409；
- 列表/详情：排序、版本列表、config revision、空列表、`fields`、`limit`/`cursor`、404；
- 权限：401、viewer 403、缺 CSRF 403、无 updater 503；
- adapter：List/Get 映射、Install/Update/Rollback/ApplyConfig 参数、ConfigSchema 正常/路径穿越/
  缺失文件/无 active/不泄漏路径。

## 7. host action 说明（需要评审）

原 `POST /plugins` 上的 `x-qwq-action: host.plugins.install` 被移除，路由改为
`x-qwq-action-exempt`。原因是：

1. `host.plugins.install` 声明为 `mode: job`，而 operations 的 host executor 只支持 `mode: invoke`；
2. 即使改成 invoke，`executeHost` 在 operations 的写事务内执行 handler，而 `updater.Install`
   自己开启 SQLite 写事务（saga/version/config），会形成嵌套写锁；
3. qwq 的 OpenAPI 规则要求 job action 路由只能 202、不能同步 200，而本任务的安装明确返回
   `PluginVersion`。

因此安装/更新/回滚/配置与 delegation、setup 一样走 catalog-exempt 直写路径。结果是
`host.plugins.install` 从 `internal/catalog/host_gen.go` 消失；`host.plugins.uninstall` 保留
（没有 executor，本就不会作为 agent tool 暴露），其指向 install 的 `undo` 已删除。
`internal/catalog/catalog_test.go` 的 `Find` 用例同步去掉 install 一项。

若后续需要保留 AI 可调用的安装动作，建议新增一个异步 operation 路由（202 + poll），而不是把同步
安装伪装成 operation。

## 8. 未做项 / 已知限制

1. **卸载**：updater 没有 Uninstall API，`DELETE /plugins/{id}` 保持 `404 NOT_FOUND`，不会假装 204。
2. **包索引/下载**：只接受上传，不实现从远端 index 拉取；`POST /plugins` 不再按 id/version 安装。
3. **回滚 revision 原子性**：updater 的 `Rollback` 不接受 expected revision；当前是 adapter 预检，
   与真正回滚之间存在窗口（每插件锁串行化 updater 调用，但不是同一事务）。
4. **幂等重放是进程内缓存**（24h TTL，容量 256，重启丢失）；与 delegations 相同。域层 revision
   仍会阻止重复变更。
5. **版本数组上限**：OpenAPI `Plugin.versions` 为 `maxItems: 200`；updater 没有版本裁剪选项，
   极端情况下版本行可能超过该上限。当前未截断。
6. **无上传进度/分块**：请求在暂存期间阻塞；前端需自行显示进度。
7. **未跑真实 systemd/updater 安装**：handler 测试使用 fake manager；adapter 参数与 updater 现有
   单测覆盖真实逻辑。P3 真机链路此前已由 `tests/e2e` 验证。
8. **配置引用复用**：客户端对敏感字段发送已有 `$secret` 引用时，`ExtractSecrets` 会把它当普通值
   再加密一次；未在本任务中改变 secrets 包语义。
9. **失败的配置 apply 会留下已提取的 secret 行**：`ExtractSecrets` 在 `ApplyConfig` 之前写 secret
   store；若插件拒绝配置，这些引用不会删除（不会泄漏明文，但会占用存储）。清理需要认出“本次新增
   且未被任何 active revision 引用”的行，secrets 包目前没有该查询，留作后续。
