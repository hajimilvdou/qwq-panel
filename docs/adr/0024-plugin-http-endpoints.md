# ADR-0024：宿主插件公开 HTTP 端点（`/p/` 动态路由）

- 状态：Approved（2026-11-13，用户直接批准本 ADR 涉及的公共 API / 网关变更;具体设计产出后由主会话评审。宿主轨实施与 p6-cap 串行）
- 日期：2026-11-13
- 关联：ADR-0002 §5（公开路由前缀与 capability）、ADR-0007（ABI 冻结）、ADR-0018（`/plugin-ui` 静态服务，p2-b）、ADR-0023（proxy.advanced 订阅，首个使用者）;ARCH §4.1/§4.1.1/§5.4/§5.5/§10；`api/qwq/platform/v1/platform.proto:402–427`（`ServePublicRoute`）
- 编号：0024（0023 归 proxy.advanced，0022 归 core.xray，0019–0021 归 P6）

## 0. 设计结论

1. **这不是新 ABI**。`ServePublicRoute` 与 `public.route:<name>` capability 已在冻结的 Platform ABI v1 与 ADR-0002 §5 中定义：宿主拥有 TLS、限流、请求体上限与 `/p/{plugin_id}/...` 路由表，剥离请求的 Cookie/Authorization/Proxy-Authorization，剥离响应的 Set-Cookie 与 hop-by-hop 头，加安全头，双向 4 MiB，无流式，匿名（actor  unset）。**缺的是宿主侧实现**——当前 `internal/` 无任何 `/p/` 路由与 dispatch 代码（已核实）。本 ADR 设计这一实现，`platform.proto` 一字不动。
2. 注册方式是**manifest 声明 + 宿主转发 UDS**：宿主从已安装验签 manifest 的 `public.route:<name>` capability 构建路由表，经每插件私有 host UDS 调 `ServePublicRoute`。不改 manifest schema（capability name/scope 模式已容纳）。
3. 鉴权分两层：**宿主**保证面板会话永不达插件（剥离会话头、Cookie `Path=/api/`）;**插件**自己做业务 token 鉴权（如订阅 token 在 URL path）。宿主不做业务鉴权。
4. 首版只解析**本机 agent** 的插件实例（standalone / controller 本机）；远端节点公开路由代理列后续。`/p/` 只路由到**已运行**插件（`live`，不拉起），未运行返回 503。
5. 与 `/plugin-ui` 严格分界：后者静态只读 GET/HEAD、版本化 immutable 缓存;前者动态、无缓存、插件逻辑处理、独立限流。

## 1. 背景与缺口

订阅链接（proxy.advanced，ADR-0023）需要**无会话、token 鉴权的动态 HTTP**：客户端（curl/订阅 App）定期拉取自己的配置。现有宿主两条路都不满足：

- `/api/v1/...`：会话 Cookie + CSRF/Origin + RBAC，订阅客户端没有面板会话。
- `/plugin-ui/{id}/{version}/...`（ADR-0018，p2-b）：只服务包内静态文件（`os.Root` 读 ui/ 子树），无动态逻辑、无 token 鉴权。

HANDOFF §约束"不提供任意 HTTP 回调给插件"指的是**通用 `HTTPRequest`/任意回调原语**（ARCH §5.4 明令禁止），不是禁止**声明式、有界、宿主中介**的公开路由。`ServePublicRoute` 正是后者：路由由验签 manifest 的 capability 声明，宿主拥有边界（限流/体上限/头剥离），插件只看到被路由的请求。本 ADR 实现它，不引入任意回调。

### 1.1 已核实现状

| 事实 | 证据 |
|---|---|
| ABI 已定义 `ServePublicRouteRequest/Response` 与 RPC，注释明确宿主职责与头剥离 | `platform.proto:402–427,671` |
| SDK 插件侧已实现 `ServePublicRoute`（默认 UNIMPLEMENTED，4 MiB 校验，状态码校验） | `sdk/pluginsdk/operations.go:162–208` |
| 宿主 `internal/` 无 `/p/` 路由、无 dispatch | grep `ServePublicRoute`/`/p/` 仅命中 SDK/tests/REPORT |
| 控制器 `PluginClient` 接口不含 `ServePublicRoute`（只有 Plan/Invoke/RunJob/Cancel） | `internal/controller/plugin_runtime.go:1520` |
| 网关有 `MountPluginUI` 挂载范式与 `hostAndOrigin` 对 plugin-ui 的 Origin 豁免 | p2-b `internal/gateway/gateway.go:344`、`middleware.go:353` |
| 网关有界令牌桶限流（per-IP pre-auth、per-principal、public-write） | `internal/gateway/ratelimit.go` |
| capability name/scope 模式容纳 `public.route` 与任意 route 名 | `api/manifest/v1/manifest.schema.json` |

## 2. 路径与注册

### 2.1 URL 形状

```text
/p/{plugin_id}/{route}/{subpath...}
```

- `plugin_id`：manifest id 语法（`^[a-z][a-z0-9]*([.-][a-z0-9]+)*$`），与 pluginui 同一安全路径分量校验。
- `route`：capability `public.route:<name>` 的 scope（`^[A-Za-z0-9._:/@-]+$` 内的单段，首版限定不含 `/`，即 `^[A-Za-z0-9._-]+$`）。
- `subpath`：传给插件的剩余路径。
- 传给插件的 `ServePublicRouteRequest.path` = `/{route}/{subpath}`（即 `/p/{plugin_id}` 之后，以 `/` 开头，符合 proto 注释）;`route` 字段单独填 route 名。例：`/p/proxy.advanced/sub/AbC…` → `route="sub"`、`path="/sub/AbC…"`。
- 方法：GET/HEAD/POST/PUT/DELETE 由插件决定;宿主不限制方法（订阅首版只用 GET），但 `hostAndOrigin` 豁免对 `/p/` 全方法生效（§3.2）。

### 2.2 路由表注册

- 来源：宿主**已安装且验签**的 manifest 的 `capabilities[]` 中 `name==public.route` 的项，scope 为 route 名。一个插件可声明多个 route。
- 路由表：`map[plugin_id]→{routes:set, instance_id}`（首版 instance=`default`）。宿主在插件安装/更新/卸载/激活状态变化时**原子重建**不可变快照（ARCH §5.7 owner 清理）；卸载即撤销路由。
- 默认关闭：未声明 `public.route` 的插件没有任何 `/p/` 入口;声明但插件未运行 → 503（§3.3）。
- 不改 manifest schema：`public.route` 是既有 capability 名，安装时按现有 capability 流程确认（敏感能力新增重新确认，ARCH §5.3）。`public.route` 风险下限 medium（未知 capability 默认，`action.go:240`），安装向导如实展示"注册公开无会话路由"。

## 3. 宿主转发与边界

### 3.1 请求处理管线

```text
client ──HTTPS──▶ Gateway
  requestID → trace → recoverPanics → securityHeaders → clientIP → hostAndOrigin
  └─ /p/ 命中：Host 白名单 + clean path（豁免 Origin/Sec-Fetch，§3.2）
     └─ publicRouteHandler:
        1. 解析 plugin_id/route/subpath，语法校验（非法 → 404，不泄露）
        2. 查路由表 + capability（未注册 → 404）
        3. per-IP 令牌桶 + 每插件在途并发上限（超限 → 429/503）
        4. 读 body ≤ 4 MiB（超限 → 413）
        5. 剥离请求头 Cookie/Authorization/Proxy-Authorization（ABI）
        6. 构造 ServePublicRouteRequest{context(匿名), route, method, path, raw_query, headers, body}
        7. live dispatch（不拉起;未运行 → 503 PLUGIN_UNAVAILABLE）
        8. 剥离响应头 Set-Cookie + hop-by-hop（ABI），加安全头
        9. 写 status + body（≤ 4 MiB）；审计（脱敏，§3.5）
```

### 3.2 网关中间件适配

- 挂载：新增 `Gateway.MountPublicRoutes(h http.Handler)`，仿 `MountPluginUI` 挂 `/p` 与 `/p/` 子树（裸前缀也应答，避免 ServeMux 重定向）；非注册 Route，不进 OpenAPI（无会话公开内容）。
- `hostAndOrigin`：把 plugin-ui 的豁免扩展到 `/p/`——**保留 Host 白名单与 `isCleanPath`**，豁免 Origin/Sec-Fetch-Site 检查（订阅客户端不是浏览器，无 Origin 或任意 Origin，无会话故无 CSRF 面）。豁免对 `/p/` 全方法生效（不限 GET/HEAD）。
- 不加 CORS 头（默认拒绝跨源浏览器读取）;订阅由 App/curl 拉取，非浏览器 XHR。
- `securityHeaders` 照常;`/p/` 响应另加 `Cache-Control: no-store`（动态、含 token 鉴权内容，禁缓存）与 `X-Content-Type-Options: nosniff`。

### 3.3 dispatch：live，不拉起

- 控制器 `PluginClient` 接口**追加** `ServePublicRoute(ctx, *ServePublicRouteRequest) (*ServePublicRouteResponse, error)`（接口内部扩展，非 ABI proto 改动）;或独立 `PublicRouteClient` 接口，由 `pluginClients.live` 解析。
- **只用 `live`**：公开请求不得拉起 on_demand 插件（防匿名流量触发插件启动/资源耗尽，与 ADR-0011 §1 子调用 live 同精神）。未运行 → 503。订阅插件 `background=true` eager 常驻，正常可用。
- deadline：每请求钳制（默认 ≤ 10s）;每插件在途公开请求上限（默认 ≤ 8，可配），超限 503 + `Retry-After`。
- 匿名 context：`RequestContext.actor` unset（ABI）;`instance_id=default`;`request_id`/`trace_id` 由宿主填;无 operation_id（公开请求不是 operation）。

### 3.4 限流与体上限

- 独立 per-IP 令牌桶（`PublicRouteLimit`，与 API pre-auth 分开）：默认 sustained 10/min、burst 20（订阅低频刷新；可配）。超限 429 + `Retry-After`。
- 每插件在途并发上限（§3.3）防单插件被打满。
- 请求/响应体各 ≤ 4 MiB（ABI 硬上限，SDK 已校验响应;宿主校验请求）。超限 413。
- 无流式（ABI v1）;大文件不走公开路由。

### 3.5 审计与脱敏

- 宿主审计每请求：`plugin_id`、`route`、`method`、`status`、`duration_ms`、`client_ip`（哈希或截断）、`request_id`。**不记完整 path/raw_query/body**——订阅 token 在 path，记全 path 等于泄露 bearer token。
- 插件侧业务审计经 `HostAuditService`（受插件配额限制，ARCH §4.2）;宿主审计与插件审计分开。
- 高频公开请求审计可聚合/采样（每 route 计数 + 错误全记），避免审计表被订阅刷新撑大;具体策略实施时定，由主会话评审。
- 错误响应 RFC 9457 Problem Details，不返回 panic/路径/内部细节。

## 4. 安全分析

| 威胁 | 分析 | 缓解 |
|---|---|---|
| 面板会话泄露给插件 | Cookie `Path=/api/`，`/p/` 收不到会话 Cookie;宿主再剥离 Cookie/Authorization/Proxy-Authorization | 双重保证（ABI + 实现）;测试断言插件收到的 headers 无会话头 |
| 插件响应泄露宿主秘密 | 插件只能返回自己的内容;宿主剥离 Set-Cookie/hop-by-hop，防插件种面板会话或走私头 | 响应头白名单/黑名单;测试 |
| SSRF | 公开路由是**入站**;插件 `PrivateNetwork=yes` 无出站，不能借机连内网。宿主 dispatch 只连本插件 UDS，target 由路由表（宿主事实）决定，**不接受请求指定任意目标** | 路由表精确匹配;无任意 URL 转发;插件无 egress |
| 路径注入/穿越 | plugin_id/route 严格语法校验;subpath 作为不透明字符串传插件，宿主不拼接文件系统路径（区别于 pluginui 的 os.Root） | 语法校验 + clean path;插件自行安全处理 subpath |
| token 泄露（日志/审计/缓存） | token 在 path;宿主审计不记 path;`Cache-Control: no-store`;建议插件用 path 而非 query 传 token | §3.5 脱敏;no-store;文档建议 |
| 匿名 DoS / 资源耗尽 | per-IP 限流 + 每插件并发上限 + 4 MiB 体上限 + live 不拉起 + deadline | §3.3/§3.4;超限 429/503 |
| 未授权路由访问 | 路由表来自验签 manifest capability;未声明即 404;capability 安装时确认 | §2.2;纵深防御 |
| 跨站请求伪造 | 公开路由无会话、无 Cookie，CSRF 无意义;业务写操作（若有）由插件 token 鉴权保护 | 宿主剥离凭证;插件负责业务鉴权 |
| 恶意响应内容（XSS） | 订阅首版 `text/plain`;宿主加 nosniff;若插件返回 HTML，浏览器直接打开（非面板 iframe），不继承面板 origin | nosniff + 无面板会话;插件内容自负 |
| Host 头注入 | 保留 Host 白名单（不豁免） | §3.2 |

**残余风险**：插件业务鉴权强度由插件负责（宿主只保证会话隔离与边界）;恶意/被攻破的内置插件可在其公开路由返回任意内容——由签名/供应链与沙箱（无 egress、无私有数据越权）收敛，与现有插件信任模型一致。

## 5. 与 `/plugin-ui` 的边界

| 维度 | `/plugin-ui/{id}/{version}/...` | `/p/{id}/{route}/...` |
|---|---|---|
| 内容 | 包内静态文件（ui/ + icon） | 插件动态逻辑 |
| 方法 | GET/HEAD | 由插件定 |
| 鉴权 | 无（公开静态） | 无会话;插件业务 token |
| 缓存 | immutable，一年 | no-store |
| 读取 | `os.Root` 宿主读文件 | UDS dispatch 到插件 |
| 版本 | URL 含版本 | 无版本（路由到 ACTIVE 实例） |
| 注册 | manifest ui/ 存在 | capability `public.route:<name>` |
| 中间件 | Host 检查，豁免 Origin（GET/HEAD） | Host 检查，豁免 Origin（全方法） |

两者都无会话、都豁免 Origin，但 `/p/` 有插件代码执行与业务鉴权，限流/审计更严。

## 6. 最小实现面

1. `internal/gateway`：`MountPublicRoutes`；`hostAndOrigin` 对 `/p/` 豁免；`PublicRouteLimit` 配置 + 令牌桶;`publicRouteHandler`（解析/查表/限流/头剥离/体上限/安全头/脱敏审计）。
2. `internal/controller`：公开路由表 resolver（从已安装验签 manifest 构建，安装/卸载/更新原子重建）;`PluginClient.ServePublicRoute`（或独立接口）+ `live` dispatch + 并发上限 + deadline。
3. 配置：`http.public_route_rate`、`http.public_route_concurrency`、`http.public_route_timeout`（默认值见 §3）。
4. 审计：脱敏公开请求审计（聚合策略待定）。
5. 文档：OpenAPI **不**含 `/p/`（无会话公开）;公共 API 文档说明前缀与边界。

**不改**：`platform.proto`、manifest schema、SDK 插件侧（已实现）、`/plugin-ui`、`/api/v1` 既有路由与鉴权。

## 7. 测试清单

**构建机单测（fake dispatcher/manifest store）**：
- 路由表：从 capability 构建、安装/卸载/更新重建、未声明 404、多 route。
- 解析：合法/非法 plugin_id/route/subpath、clean path、裸前缀 `/p`、方法。
- 头剥离：请求 Cookie/Authorization/Proxy-Authorization 被剥;响应 Set-Cookie/hop-by-hop 被剥;安全头/no-store 存在。
- 限流：per-IP 超限 429 + Retry-After;每插件并发超限 503;体超限 413。
- dispatch：live 未运行 503（不拉起）;deadline 钳制;匿名 context（actor unset、无 operation_id）。
- 中间件：`/p/` 豁免 Origin/Sec-Fetch 但保留 Host 白名单;非白名单 Host 拒绝;`/api/` 与 `/plugin-ui` 行为回归不变。
- 审计脱敏：断言审计记录不含完整 path/token/body。
- 路由计数回归：`TestRegisterPublicRoutes` 等既有路由数测试更新（`/p/` 是非注册 mount，不影响 OpenAPI 路由数;断言）。

**集成（测试机，届时先经用户确认）**：
- 真实 proxy.advanced 订阅：`curl /p/proxy.advanced/sub/{token}` 返回 VLESS 链接;无效 token 404;停用 403;会话 Cookie 不被插件收到;限流生效。
- 1C1G：订阅并发上限下的内存/延迟;审计聚合不撑大表。

## 8. 批准记录与评审

**公共 API / 网关变更已于 2026-11-13 经用户直接批准。** 下列设计要点在批准范围内，实施细节（默认值调优、审计聚合策略、接口形态）产出后由主会话评审：

1. 新增公开前缀 `/p/{plugin_id}/{route}/...` 与 `MountPublicRoutes`、`hostAndOrigin` 豁免扩展。
2. 公开路由限流/并发/体上限默认值（per-IP 10/min burst 20、每插件在途 ≤ 8、4 MiB、deadline ≤ 10s）与配置项。
3. live-only dispatch（公开请求不拉起插件，未运行 503）。
4. 审计脱敏与聚合策略（不记 path/token/body;高频聚合）。
5. 首版只解析本机 agent 实例，远端节点公开路由代理列后续。

## 9. 代价

- 网关新增公开入口与中间件豁免，需安全审查与回归（确保 `/api/`、`/plugin-ui` 不受影响）。
- 控制器 `PluginClient` 接口扩展与公开路由表 resolver（owner 清理）。
- 公开入口扩大攻击面（匿名可达），由限流/并发/体上限/live-only/头剥离/脱敏收敛;插件业务鉴权自负。
- 与 p6-cap 同改 hostsvc/gateway，需串行协调（任务拆解登记）。
