# P1-T7：API 网关核心与事件流

- 状态：实现与测试完成，等待 `internal/controller` 装配（本包不含资源处理器）
- 范围：`internal/gateway/**`、`internal/events/**`
- 依据：`IMPLEMENTATION-PLAN.md` P1-T7、`docs/ARCHITECTURE.md` §4.1/§4.1.1/§4.2/§13、ADR-0004 D2/D3/D8/D9、ADR-0006 D2、ADR-0008 §4
- 约束：不改 `go.mod`/`go.sum`、不改其他包；未引入 YAML 依赖（契约测试用标准库按行解析 `openapi.yaml`）

## 1. 交付内容

### 1.1 `internal/events`（事件日志尾随与分发）

| 文件 | 内容 |
|---|---|
| `events.go` | `Event`（公共 Event 线格式）、`Convert(storage.Event)`、`Filter`（topic 精确/`.*` 前缀 + subject 前缀）、`Visibility` 与 `AllowAll`/`DenyAll`、delivery class 与 resync reason 常量 |
| `hub.go` | `Hub`：**单条共享尾随循环** + 按订阅重放 + 有界缓冲 + 丢弃/resync 计数 + 保留清理；`Journal` 窄接口（`*storage.DB` 直接满足）；`Retain`、`Stats` |
| `lossy.go` | `Lossy`：实时有损通道（指标、在线状态），内存固定容量、按 key 合并最新值、丢弃计数，不写日志 |
| `*_test.go` | fake journal（内存实现，含 `WaitAfter` 语义与 blockReads 闸门）、16 个测试 |

设计要点：

- **一个循环读日志**：`Hub.Run` 内 `WaitAfter(cursor)` 阻塞等待提交水位，唤醒后 `EventsAfter` 批量读一次，再分发给所有订阅者；订阅/关闭通过取消当前 wait 唤醒循环（`Subscribe`/`Close` → `cancelWait`），不存在每订阅者轮询。`hasWorkLocked` 在同一把锁下检测待办，避免"唤醒丢失"；`TestSharedTailLoopReadsOnceForAllSubscribers` 断言两个订阅者只增加常数次日志读。
- **从任意 seq 续传**：`SubscribeOptions.Since`（<0 = 仅实时；0 = 从最旧保留事件开始；>0 = 从该 seq 之后）。重放由 hub 在循环内按批读取并投递；重放目标 `replayTo` 取订阅时刻的 head，若循环已读到更后面则自动延长（`resumeFrom`/`replayTo`），因此重放与实时切换不丢事件、不重复投递。
- **resync**：`Start.Resync/Reason`。保留窗口不足 → `retention_exceeded`；客户端 seq 大于 head（恢复备份/换实例）→ `server_restart`；重放期间缓冲溢出 → 断开该订阅（`Overflowed()` 为真，网关发 `buffer_overflow` 后关流）。`buffer_overflow` 的计数在 `Stats.Dropped`，`retention_exceeded`/`server_restart` 在 `Stats.Resyncs`。
- **有界**：每订阅缓冲默认 256（`sse_buffer_events`，可覆盖，上限 4096）；订阅总数默认 1024（`ErrTooManySubscribers`）；慢消费者永不阻塞发布者（非阻塞投递，满即移除并关 channel）。
- **可见性默认拒绝**：`Visibility` 为 nil 时不投递任何事件；真实实现由 `internal/authz` 在装配时提供。
- **保留**：`pruneLoop` 由 `clock.Clock` 驱动（`Clock.After`），按"保留条数与时长取并集"调用 `PruneEvents(keep, minAge, batch)`；清理前把 `keep` 提升到待重放订阅仍需要的范围，避免清理掉正在重放的事件。
- **统计**（ARCH §13）：`Subscribers/MaxSubscribers`、`Dropped`、`Resyncs`、`Replayed`、`Pruned`、`Failed`、`Delivered`。
- **有损通道**：每订阅以 key→最新值 保存（容量默认 64 key），`Publish` 合并/丢弃并计数，`Next(ctx)` 取下一个待发样本；主题数、每主题订阅数均有上限，不写日志、不重放。

### 1.2 `internal/gateway`（HTTP 信任边界）

| 文件 | 内容 |
|---|---|
| `gateway.go` | `Config`/`Limits`/`StreamConfig`、`New`、`ServeHTTP`、`Close`、`AddCheck`、trusted proxies / public origins 解析、路径规范化 |
| `middleware.go` | 全局中间件与路由级中间件、凭据解析、ClientIP、Origin/Host、CSRF、凭据策略、限流、幂等键要求 |
| `routes.go` | `Route`/`Access`/`BodyMode`、`Handle`、路由表、`Allow` 与 405、`Routes()` |
| `response.go` | `responseWriter`（状态与 panic 判断、`Unwrap`）、`WriteJSON`、`EncodeJSON`、`writeProblem`、`payloadTooLarge` |
| `decode.go` | 严格 JSON 解码：体积、嵌套深度（解码前流式扫描）、未知字段、类型错误（JSON Pointer）、尾随数据；字段表缓存按类型有界 |
| `projection.go` | `Projection`：`fields` 解析（RFC 6901、≤32、拒绝索引段、256 字节上限）与投影 |
| `params.go` | `ListQuery`（fields/since_revision/cursor/limit）、`ParseTopics`、`ParseSequence`、`IdempotencyKey`、`ExpectedRevisionQuery` |
| `cookie.go` | 会话 Cookie 名与写入/清除（`HttpOnly; Secure; SameSite=Lax; Path=/api/`） |
| `health.go` | `Check`、`/healthz`、`/readyz`（503 `UNAVAILABLE`，细节只进日志） |
| `sse.go` | `GET /api/v1/events`、帧写入器（写超时+Flush）、每主体连接上限、resume/resync/心跳 |
| `ratelimit.go` | `Limiter` 接口与有界内存令牌桶 `TokenBuckets` |
| `*_test.go` | 8 个测试文件；含用真实 storage 提交 `resource.changed` 的 SSE 端到端测试与 openapi 契约测试 |

## 2. 导出 API（集成用）

### 2.1 构造与装配

```go
func New(cfg Config) (*Gateway, error)   // 内部注册 /healthz、/readyz、GET /api/v1/events
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request)  // *Gateway 即 http.Handler
func (g *Gateway) Handle(rt Route) error // 启动前注册路由
func (g *Gateway) Routes() []RouteInfo   // 契约测试/doctor
func (g *Gateway) Close()                // 结束所有 SSE 流（http.Server 仍需自行 Shutdown）
func (g *Gateway) AddCheck(c Check) error
func (g *Gateway) StreamSlots() (total, principals int)
```

`Config`：`Logger`、`Clock`、`IDs`、`TrustedProxies`、`PublicOrigins`、`TLS`、`InsecureCookies`、`Auth`、`RateLimit`、`PreAuthLimit`、`PublicWriteLimit`、`Limits`、`Events`、`Visibility`、`Stream`、`Checks`。

### 2.2 需要其他包实现的窄接口

```go
// 由 internal/controller 适配 identity + authz
type Authenticator interface {
    Authenticate(ctx context.Context, c Credentials) (Principal, error)
}
type Credentials struct { Session, Bearer string }
type Principal struct {
    Actor  actor.Actor
    Scheme Scheme   // SchemeSession | SchemeService | SchemeDelegation
    CSRF   string   // 仅会话：identity.Session.CSRF
}
var ErrNoCredentials = errors.New(...)

type Limiter interface { Allow(key string) (ok bool, retryAfter time.Duration) }
type Check struct { Name string; Check func(ctx context.Context) error }
```

`Visibility` 直接使用 `events.Visibility`（`func(actor.Actor, events.Event) bool`）。

### 2.3 路由声明

```go
type Route struct {
    Method, Pattern string
    Handler http.Handler
    Access Access              // 零值 AccessDenied：一律 403，避免忘配
    Body BodyMode              // BodyNone / BodyJSON / BodyPluginJSON
    RequireIdempotency bool
    NoRateLimit bool
}
```

`Access` 与 OpenAPI `security` 的对应：

| OpenAPI security | Access |
|---|---|
| `[]`（/healthz、/readyz、/api/v1/setup、GET /api/v1/setup） | `AccessPublic` |
| `[sessionCookie]`（审批决定、委托管理、会话） | `AccessSession` |
| `[sessionCookie, serviceAccountToken]`（其余 REST） | `AccessSessionOrService` |
| `[delegationToken]`（`/api/v1/agent/*`） | `AccessDelegation` |

### 2.4 处理器工具

```go
func (g *Gateway) DecodeJSON(r *http.Request, dst any) error  // 严格解码，错误即 *problem.Error
func (g *Gateway) ListQuery(r *http.Request) (ListQuery, error)
func (g *Gateway) SetSessionCookie(w, value string, ttl time.Duration)
func (g *Gateway) ClearSessionCookie(w http.ResponseWriter)
func WriteJSON(w http.ResponseWriter, status int, v any) error
func EncodeJSON(w io.Writer, v any) error
func ParseFields(raw string, max int) (*Projection, error)
func (p *Projection) Apply(doc map[string]any) (map[string]any, error)
func IdempotencyKey(r *http.Request) (string, error)
func ExpectedRevisionQuery(r *http.Request) (string, error)
func ParseTopics(values []string, max int) ([]string, error)
func ParseSequence(raw string) (int64, bool)
func RequestID(ctx) / TraceID(ctx) / ClientIP(ctx) string
func PrincipalFrom(ctx) (Principal, bool)
const SessionCookieName = "__Secure-qwq_session"
```

## 3. 中间件顺序（固定，信任边界）

全局（包装 mux）：

```text
requestID(X-Request-Id) → trace(traceparent 或生成) → panic 恢复(INTERNAL+堆栈日志)
→ 安全头 → ClientIP(只信任 trusted_proxies 的 XFF/XFH) → Host/Origin 白名单 + 路径规范化 → 路由
```

路由级（`routes.go` 统一组合，调用方无法改序）：

```text
请求体大小(max_body_bytes / max_plugin_body_bytes) + Content-Length 快速失败
→ Content-Type(application/json, 否则 415)
→ 按客户端 IP 限流（PreAuthLimit，IPv6 按 /64 聚合；未认证写请求改用 PublicWriteLimit；健康探针豁免）
→ 认证(Authenticator → Principal, 无凭据 401)
→ CSRF（仅会话凭据的变更请求，SHA-256 后再常量时间比较）+ Origin/Host 已在全局校验
→ 凭据策略（该路由接受的 Scheme；委托令牌只能用于 agent 路由）
→ 按主体限流（RateLimit；公开路由按 IP；健康探针豁免）
→ Idempotency-Key 必填校验
→ 处理器
```

补充：
- 未知路径 → 404 `NOT_FOUND`；已知路径未知方法 → 405 `METHOD_NOT_ALLOWED` + `Allow`；两者都是 `application/problem+json`。
- 路径不做 301 规范化（尾斜杠、`//`、`.`/`..` 一律 404）。
- 安全头：`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`、`Content-Security-Policy: frame-ancestors 'none'`、`Cache-Control: no-store`，`TLS=true` 时加 `Strict-Transport-Security: max-age=15552000`；另加 `X-Request-Id`、`X-Trace-Id`（后者是 OpenAPI 之外的兼容扩展）。
- 客户端 `X-Request-Id` 仅在 ≤64 且字符集安全时沿用，否则重新生成（`ids.Request` 前缀 `req_`）。

## 4. SSE 帧格式（`GET /api/v1/events`）

```text
retry: 3000
event: ready
data: {"head_sequence":"0","heartbeat_seconds":15}

id: 42
data: {"event_id":"evt_…","sequence":"42","type":"resource.changed","schema_version":"1",
       "subject":"nodes/local","occurred_at":"2026-11-01T12:00:00.000Z",
       "actor":{"kind":"ai_agent","id":"dlg_…","on_behalf_of":"usr_…"},
       "trace_id":"…","operation_id":"…","delivery_class":"reliable",
       "payload":{"subject":"nodes/local","revision":"42","kind":"update",…}}

event: heartbeat
data: {"head_sequence":"42","server_time":"2026-11-01T12:00:15.000Z"}

event: resync
data: {"reason":"retention_exceeded","head_sequence":"42","topics":["resource.changed","operation.updated"]}
```

- 域事件帧没有 `event:` 行（`EventSource.onmessage`），`id:` = seq，`data:` 单行 JSON；控制帧（ready/heartbeat/resync）有 `event:` 且无 `id:`，不移动 `Last-Event-ID`。
- 支持 `Last-Event-ID` 头（优先）与 `last_event_id` 查询参数；早于保留窗口先发 `resync` 再发 `ready`；溢出时发 `resync(buffer_overflow)` 后关流。
- 心跳默认 15 s（配置 < 30 s），每帧 `Flush` 且设置写截止时间（默认 10 s）；服务关闭（`Gateway.Close`）或请求取消时结束流。
- 每主体连接数默认 8（`limit.name = sse_connections_per_principal`，429），总连接数默认 1024（503 `UNAVAILABLE`）。
- `topics` 逗号分隔、≤16、`^[a-z][a-z0-9_.-]*(\.\*)?$`；缺省 `resource.changed,operation.updated`。

## 5. 与 OpenAPI 的对应与不一致

对应：

- `x-qwq-limits`：`max_body_bytes`(1 MiB)、`max_plugin_body_bytes`(4 MiB)、`max_json_depth`(64)、`list_limit_default`(50)/`max`(200)、`fields_max`(32)、`sse_topics_max`(16)、`sse_buffer_events`(256)、`sse_heartbeat_seconds`(15) 全部落在 `Limits`/`StreamConfig` 默认值；错误里的 `limit.name`/`limit.max` 用同名。
- `Problem` 各字段由 `internal/platform/problem` 生成（P1-T1 已用测试对照 `ProblemCode` 枚举）。
- `IdempotencyKeyValue`（16..128，`[A-Za-z0-9_.:-]`）、`Revision`（≤64，`[A-Za-z0-9._~-]`）、`Cursor`（≤512）、`Sequence`（≤20 位十进制）、`JsonPointer`（≤256）逐条校验，违规指针落在 `/Idempotency-Key`、`/since_revision`、`/cursor`、`/limit`、`/fields`，`in` 标 header/query。
- `HealthStatus`、`StreamReady`、`StreamHeartbeat`、`StreamResync` 与 `Event` 字段一致（`events.Event`）。

不一致 / 需要拍板：

1. **resync 与 ready 的顺序**：任务要求"早于最旧保留条目时先发 resync"，OpenAPI 描述却是 "`event: ready` is sent first"。实现按任务先 resync 再 ready（客户端先重载快照再处理后续帧更安全）。若要求严格照文档，只需把 `sse.go` 中两段写帧调用对调。
2. **HEAD**：Go 1.22 `ServeMux` 的 `GET` 模式同时匹配 HEAD（响应体由 server 丢弃）；OpenAPI 只声明 GET。未额外拒绝 HEAD。
3. **`fields` 的"标识符"**：OpenAPI 说结果"plus the identifier and `revision`"。实现保留全部顶层 `id`/`*_id` 与 `revision`（比"单个标识符"更宽，便于合并缓存）。
4. **限流参数**：`x-qwq-limits` 没有限流项；`internal/controller` 装配三个 `TokenBuckets`（默认值为本包导出常量）：`PreAuthLimit` 每 IP 10 rps / burst 50、`PublicWriteLimit` 每 IP 0.2 rps / burst 10、`RateLimit` 每主体 20 rps / burst 100；每个表最多 10000 个 key，满后 O(1) 淘汰最久未用者。429 带 `Retry-After` 与 `retry_after`，但不填 `limit`（接口不返回上限值）。
5. **SSE 每主体连接上限**不是 OpenAPI 参数，用 429 + `limit.name=sse_connections_per_principal` 表达。
6. **深度超限**返回 `PAYLOAD_TOO_LARGE`（`limit.name=max_json_depth`），与 `PayloadTooLarge` 响应说明一致。
7. **未生成 `sdk/gen/publicapi`**（P1-T1 未落地 oapi-codegen 产物），所以 `HealthStatus`/`Stream*` 在网关内本地定义；集成时若改用生成模型，只替换这几个结构体与 SSE 事件编码，不影响中间件与路由。
8. **网关只校验形状**：required/pattern/业务校验属于各资源处理器（生成模型 + 领域包）；`DecodeJSON` 负责"体积/深度/未知字段/类型/JSON Pointer"。

## 6. 待实现路由（契约测试打印，集成后应为空）

`TestOpenAPIRouteContract` 解析 `../../api/public/v1/openapi.yaml`，要求网关注册的路由全部存在于文档中（否则失败），并打印文档中尚未实现的 40 条：

```text
DELETE /api/v1/delegations/{delegation_id}      GET  /api/v1/operations
DELETE /api/v1/plugins/{plugin_id}              GET  /api/v1/operations/{operation_id}
DELETE /api/v1/sessions/current                 GET  /api/v1/plans/{plan_id}
DELETE /api/v1/users/{user_id}                  GET  /api/v1/plugins
GET    /api/v1/approvals                        GET  /api/v1/plugins/{plugin_id}
GET    /api/v1/approvals/{approval_id}          GET  /api/v1/sessions/current
GET    /api/v1/delegations                      GET  /api/v1/setup
GET    /api/v1/delegations/{delegation_id}      GET  /api/v1/users
GET    /api/v1/nodes                            GET  /api/v1/users/{user_id}
GET    /api/v1/nodes/{node_id}                  PATCH /api/v1/delegations/{delegation_id}
PATCH  /api/v1/users/{user_id}                  POST /api/v1/agent/cancel
POST   /api/v1/agent/describe_action            POST /api/v1/agent/execute
POST   /api/v1/agent/find_actions               POST /api/v1/agent/plan
POST   /api/v1/agent/read                       POST /api/v1/agent/wait
POST   /api/v1/approvals/{approval_id}/decision POST /api/v1/delegations
POST   /api/v1/nodes/{node_id}/plugins/{plugin_id}/instances/{instance_id}/operations/{operation}
POST   /api/v1/operations/{operation_id}/cancel POST /api/v1/plans
POST   /api/v1/plans/{plan_id}/execute          POST /api/v1/plugins
POST   /api/v1/plugins/{plugin_id}/operations/{operation}
POST   /api/v1/sessions                        POST /api/v1/sessions/mfa
```

已实现（3 条）：`GET /healthz`、`GET /readyz`、`GET /api/v1/events`。另需说明：插件公开路由 `/p/{plugin_id}/…` 不在公共 API 文档里，也尚未注册；会话 Cookie `Path=/api/` 已保证其收不到会话。

## 7. 测试清单与结果

`internal/events`（`go test -race`，约 1.9 s）：

- `TestConvert`：seq 字符串化、时间戳、actor、payload 压成单行。
- `TestLiveDeliveryAndTopicFilter` / `TestSubjectPrefixFilter`：精确 topic、`.*` 前缀、subject 前缀。
- `TestReplayFromSequence`：从 seq 续传后转实时，顺序与去重。
- `TestReplayOverflowDisconnectsSubscriber`：缓冲 2、重放 4 条 → 断开、`Overflowed`、`Dropped` 计数、订阅数归零。
- `TestResyncWhenRetentionPassed` / `TestResyncWhenClientAhead`：两种 resync 原因与 `Stats.Resyncs`。
- `TestRefusesTooManySubscribers`：`ErrTooManySubscribers`。
- `TestVisibilityIsEnforced`：按主体过滤；nil 可见性拒绝一切。
- `TestCloseEndsSubscription` / `TestSubscribeAfterClose`：关闭语义与 `ErrClosed`。
- `TestSharedTailLoopReadsOnceForAllSubscribers`：两个订阅者只读常数次日志。
- `TestPruneFollowsClock` / `TestPruneKeepsEventsNeededByReplay`：fake clock 驱动清理、keep 被待重放订阅抬高、`Stats.Pruned`。
- `TestStatsCounters`、`TestLossy*`：统计与有损通道（合并、丢弃、上限、ctx 取消）。

`internal/gateway`（`go test -race`，约 8.1 s）：

- `TestSecurityHeadersRequestIDAndTrace`、`TestRequestIDIsEchoedWhenWellFormed`、`TestMalformedRequestIDIsReplaced`、`TestTraceparentIsContinued`、`TestInvalidTraceparentIsIgnored`、`TestHSTSOnlyOverTLS`。
- `TestPanicBecomesProblemWithoutLeaking`：500 `INTERNAL`，响应不含 panic 文本/堆栈，日志含堆栈与 request_id。
- `TestBodyTooLarge`（413 + `limit`）、`TestJSONDepthLimit`（413 + `max_json_depth`）、`TestUnsupportedMediaType`（415，含 charset 正例）。
- `TestClientIPTrust`：不受信任代理的 XFF 被忽略、受信任代理生效、链式跳过受信任跳、畸形链不半信、单 IP 条目也受信任。
- `TestOriginAndHostChecks`：坏 Origin/坏 Host 403、回环 Host 放行、`Sec-Fetch-Site` cross-site/same-site、未配置白名单时同源放行。
- `TestCSRFProtection`：缺 token/错 token 403、正确通过、Bearer 不需要 CSRF。
- `TestCredentialPolicy`：无凭据 401、委托令牌在普通路由 403、服务账号在会话路由 403、会话在 agent 路由 403、委托在 agent 路由通过、未知会话 401、未声明策略的路由一律 403。
- `TestAuthenticationNotConfigured`、`TestAuthenticatorFailureIsProblem`、`TestAuthenticatorInternalErrorIsHidden`。
- `TestRateLimited` + `TestTokenBuckets`（令牌桶补充、上限与淘汰、探针豁免）。
- `TestDecodeJSONHelper`：合法、未知字段（`/extra`、`/nested/bogus`）、类型错误（`/count`）、坏 JSON、尾随数据、空体。
- `TestIdempotencyKeyEnforced`、`TestListQueryDefaultsAndValidation`、`TestParseTopics`、`TestParseSequence`、`TestIdempotencyKey`、`TestExpectedRevisionQuery`、`TestParseFields`、`TestProjectionApply`、`TestProjectionNilIsIdentity`。
- `TestUnknownPathIsProblemNotFound`（含尾斜杠/双斜杠/`..` 不重定向）、`TestMethodNotAllowedCarriesAllow`、`TestHandleValidation`、`TestRoutesAreListedSorted`、`TestOpenAPIRouteContract`。
- `TestHealthzAndReadyz`、`TestReadyzReportsUnavailableWithoutLeaking`、`TestCheckValidation`、`TestReadyzHonoursCheckTimeout`。
- SSE（真实 `storage.DB` + `events.Hub` + `httptest`）：`TestStreamSendsReadyFirst`、`TestStreamDeliversEventAndHeartbeat`、`TestStreamResumesFromLastEventID`、`TestStreamResumePrefersHeaderOverQuery`、`TestStreamResumeFromZeroReplaysEverything`、`TestStreamResyncAfterRetention`（真实 `PruneEvents`）、`TestStreamResyncWhenClientIsAhead`、`TestStreamTopicFilter`、`TestStreamVisibilityIsEnforced`、`TestStreamPerPrincipalLimit`、`TestStreamRejectsBadResumeSequence`、`TestStreamRejectsForeignOrigin`、`TestStreamRequiresAuthentication`、`TestStreamClosesOnGatewayShutdown`、`TestStreamOverflowSendsResyncAndCloses`（120 条 2 KiB 事件 → `buffer_overflow` 后关流）、`TestAIModificationReachesStreamWithinOneSecond`（ADR-0004 验收 2：`Tx.Changed` 提交到帧到达 < 1 s，`payload.revision == sequence`、`changed_pointers=[/name]`、actor 为 `ai_agent`）。
- `TestCookieAttributes`：`__Secure-qwq_session` + `Path=/api/; HttpOnly; Secure; SameSite=Lax`，清除用 `Max-Age=0`。

## 8. 执行过的命令与结果

在构建机 `/root/qwq-dev/p1d`（`$env:QWQ_REMOTE_SRC='p1d'`，Go 1.27.3 linux/amd64）：

```text
gofmt -w internal/events internal/gateway   # 无输出
go vet ./internal/events/... ./internal/gateway/            # 通过
staticcheck ./internal/events/... ./internal/gateway/       # 通过（已修 U1000 两处）
CGO_ENABLED=1 go test -race -count=1 ./internal/events/... ./internal/gateway/
    ok  github.com/qwq-panel/qwq/internal/events   1.852s
    ok  github.com/qwq-panel/qwq/internal/gateway  8.229s
gofmt -l internal/events internal/gateway                   # 无输出
go test -run TestOpenAPIRouteContract -v ./internal/gateway/ # 40/43 待实现，未失败
```

只测了本任务的两个包；未运行其他包、未改 `go.mod`/`go.sum`、未 `git add`/`commit`。

## 9. 依赖与需要其他包配合的事项

1. **无新依赖**。YAML 未引入：契约测试按行解析 `openapi.yaml` 的 `paths:` 段（文档缩进固定；若以后格式变化，需要改为正式 YAML 解析或明确申请依赖）。
2. **`internal/controller` 需要提供 Authenticator 适配器**（示意）：

```go
func (a adapter) Authenticate(ctx context.Context, c gateway.Credentials) (gateway.Principal, error) {
    if c.Session != "" {
        act, sess, err := a.identity.AuthenticateSession(ctx, c.Session)
        if err != nil { return gateway.Principal{}, err }   // identity 返回 *problem.Error，网关原样输出
        return gateway.Principal{Actor: act, Scheme: gateway.SchemeSession, CSRF: sess.CSRF}, nil
    }
    if c.Bearer != "" { /* authz 解析委托/服务账号令牌 */ }
    return gateway.Principal{}, gateway.ErrNoCredentials
}
```

   建议在 controller 的测试里断言 `gateway.SessionCookieName == identity.SessionCookieName`（两处都是 `__Secure-qwq_session`，网关不 import identity）。
3. **`events.Visibility` 由 authz 提供**：签名是同步的 `func(actor.Actor, events.Event) bool`，必须快、不能回调 hub。可用 `authz.RoleAllows(role, "host.<resource>:read")` 按事件 subject 的首段映射资源；委托令牌要再与委托策略求交（拿不到 role 时保守拒绝，hub 默认拒绝）。
4. **装配顺序**（建议）：`storage.Open` → `events.New` + `go hub.Run(ctx)` → `gateway.New(Config{...})` → `Handle` 逐个注册资源路由 → `AddCheck(db.QuickCheck)`、TLS 证书有效期检查 → `http.Server{Handler: g}`；关停时先 `g.Close()`（结束 SSE）再 `srv.Shutdown`，最后 `hub.Close()`。
5. **资源处理器约定**：变更路由要设 `Body: BodyJSON`（插件负载用 `BodyPluginJSON`），按 `x-qwq-idempotency` 设 `RequireIdempotency`；处理器内用 `g.DecodeJSON`、`gateway.WriteJSON`、`problem.Write`、`g.ListQuery` 的 `Fields/SinceRevision/Cursor/Limit`。`202` 响应自行设 `Location`，与 `Idempotency-Replayed` 等头一起由领域层决定。
6. **身份适配的 MFA/审批限制**：`actor.Actor.MFA` 由 identity 适配器填；"批准只接受真人会话"由 `AccessSession` + 领域层 `Actor.IsHumanSession()` 共同保证。
7. **插件公开路由** `/p/{plugin_id}/…` 若由同一监听器提供，需要单独注册 `AccessPublic` 路由（并能从 `gateway.ClientIP(ctx)` 取真实 IP）；它不该走 CSRF/会话逻辑，也不在 OpenAPI 中。
8. **可观测性接线**：`hub.Stats()` 与 `gateway.StreamSlots()` 建议在 `qwq doctor`/指标端点暴露（丢弃数、resync 数、活动订阅数）。
