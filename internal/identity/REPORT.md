# P1-T3 身份 + P1-T4 操作者与授权：实现报告

> 范围：`internal/identity/**`、`internal/authz/**`、`internal/storage/migrations/0002_identity.sql`、`0003_authz.sql`
> 依据：`IMPLEMENTATION-PLAN.md` P1-T3/T4、`docs/ARCHITECTURE.md` §4.1/§4.1.1/§10.3、ADR-0004 D4/D6/D10、ADR-0005 Q7、ADR-0008、`api/public/v1/openapi.yaml`
> 状态：两个包可编译、可测试；导出接口稳定，供 `internal/controller` 组装。

## 1. 交付概览

| 内容 | 位置 |
|---|---|
| 身份领域（用户/口令/会话/TOTP/恢复码/初始化 token/退避/审计接口/ResetAdmin） | `internal/identity/`（13 个源文件 + 8 个测试文件） |
| 授权领域（权限/角色/委托/服务账号/速率限制/CanApprove） | `internal/authz/`（9 个源文件 + 4 个测试文件） |
| 身份表结构 | `internal/storage/migrations/0002_identity.sql` |
| 授权表结构 | `internal/storage/migrations/0003_authz.sql` |

两个领域包互不导入，也不导入 `internal/operations`、`internal/secrets`、`internal/gateway`。
跨包能力用窄接口表达，由主会话在 `internal/controller` 注入：

- `identity.SecretSealer`（`Seal/Open`）→ 由 `internal/secrets` 实现；TOTP 密钥只以 `sec_…` 引用入库。
- `identity.Auditor`（`Audit(ctx, tx, AuditRecord)`）→ 由 `internal/operations` 实现（审计表归它所有）。
- `authz.PrincipalSource`（`PrincipalRole(ctx, userID) (role string, disabled bool, err error)`）→ **`identity.Service` 已实现同名方法**，可直接赋值：`authz.New(authz.Options{Principals: identitySvc, …})`。

## 2. 数据模型

### 2.1 `0002_identity.sql`

```text
users(user_id PK, username UNIQUE, display_name, role, disabled, created_at, updated_at, revision)
  CHECK role IN ('admin','operator','viewer')；CHECK username = lower(username)；
  CHECK length(username) 1..64；display_name <= 128

credentials(credential_id PK, user_id → users ON DELETE CASCADE, type, secret, data JSON,
            counter, created_at, updated_at, revision)
  type ∈ password | totp | totp_pending | recovery | webauthn | oidc
  INDEX (user_id, type)
  UNIQUE INDEX (user_id) WHERE type='password' / 'totp' / 'totp_pending'
  secret 语义：password = argon2id PHC；totp/totp_pending = 密封引用；recovery = 规范化码的 SHA-256(hex)
  data：类型相关的 JSON（totp_pending 存 {expires_at}；webauthn/oidc 预留 credential 元数据）
  counter：TOTP 最近接受的时间片（拒绝重放），WebAuthn 以后可放 signCount

sessions(session_id PK, user_id → users ON DELETE CASCADE, token_hash BLOB UNIQUE,
         csrf_token, mfa_verified_at, created_at, last_seen_at, idle_expires_at,
         expires_at, revoked_at, client_ip, user_agent)
  INDEX (user_id)、(expires_at)、部分索引 (user_id) WHERE revoked_at=''

mfa_challenges(id_hash BLOB PK, user_id → users ON DELETE CASCADE, created_at,
               expires_at, used_at, attempts, client_ip)
  INDEX (user_id)

one_time_tokens(token_id PK, purpose, user_id NULL → users ON DELETE CASCADE,
                token_hash BLOB UNIQUE, created_at, expires_at, used_at)
  purpose ∈ setup | enroll；INDEX (purpose, used_at)
```

`credentials` 的 `(type, secret, data)` 形状就是为 WebAuthn/OIDC 预留的：新增类型只写 `data`，不改表（ADR-0005 Q7）。
`sessions.csrf_token` 明文保存是刻意的：`GET /sessions/current` 必须把它返回给 Shell；CSRF token 只防跨站请求，不防数据库泄露，而会话 token 本身只存 SHA-256。

### 2.2 `0003_authz.sql`

```text
delegations(delegation_id PK, owner_id → users ON DELETE CASCADE, label, token_hash BLOB UNIQUE,
            token_prefix, policy JSON, status ∈ active|suspended|expired, created_by,
            created_at, updated_at, expires_at, last_used_at, revision)
  INDEX (owner_id,status)、(expires_at)

service_accounts(service_id PK, name UNIQUE, role ∈ 内置角色, token_hash BLOB UNIQUE,
                 token_prefix, disabled, created_by, created_at, updated_at,
                 last_used_at, revision)
  INDEX (disabled)
```

- 删除用户会级联删除会话、凭据、挑战、初始化 token、委托（`foreign_keys=1`）。
- "停用用户即失效委托"不靠删除：每次鉴权都用 `PrincipalSource` 重新读 `disabled` 与 `role`，因此停用/降级立即生效（ADR-0004 D4）。
- `delegations.status` 的 `expired` 是读时计算（`Delegation.StatusAt(now)`），不为了过期去写一行动手改状态。

### 2.3 迁移注意

0002/0003 原本是 `SELECT 1` 占位。迁移校验和按文件内容计算，**已经用旧占位建过库的本地开发库会报 `migration 0002_identity was changed after it was applied`**；集成/开发时需要删除该 SQLite 文件重建（尚无线上库）。`internal/storage` 不需要改动。

## 3. identity 导出 API（集成用）

```go
// 构造
type Options struct {
    DB *storage.DB; Clock clock.Clock; IDs *ids.Generator; Logger *slog.Logger
    Sealer SecretSealer; Auditor Auditor; Hasher *Hasher; Throttle *LoginThrottle
    PasswordPolicy *PasswordPolicy
    IdleTimeout, AbsoluteTimeout, TouchInterval, SetupTokenTTL, EnrollmentTokenTTL,
    MFAChallengeTTL, TOTPEnrollmentTTL, MFAFreshness time.Duration
    MaxMFAChallengeAttempts int
}
func New(Options) (*Service, error)
func (s *Service) Clock() clock.Clock

// 用户（读）
func (s *Service) User(ctx, userID) (User, error)
func (s *Service) UserByUsername(ctx, username) (User, error)
func (s *Service) ListUsers(ctx, ListUsersInput{Role, After, Limit}) ([]User, error)
func (s *Service) PrincipalRole(ctx, userID string) (role string, disabled bool, err error)  // authz.PrincipalSource

// 用户（写：调用方 *storage.Tx + expected_revision）
func (s *Service) CreateUser(ctx, tx, CreateUserInput{Username, DisplayName, Role, PasswordHash, Actor}) (CreateUserResult{User, EnrollmentToken, EnrollmentUntil}, error)
func (s *Service) UpdateUser(ctx, tx, UpdateUserInput{UserID, ExpectedRevision, DisplayName *string, Role *Role, Disabled *bool, Actor}) (User, error)
func (s *Service) DeleteUser(ctx, tx, DeleteUserInput{UserID, ExpectedRevision, Actor}) error
func (s *Service) ResetPassword(ctx, tx, ResetPasswordInput{UserID, ExpectedRevision, PasswordHash, KeepSessions, Actor}) (User, error)
func (s *Service) PreparePassword(ctx, username, password) (string /*PHC*/, error) // 事务外哈希

// 初始化与注册
func (s *Service) SetupInitialized(ctx) (bool, error)
func (s *Service) NewSetupToken(ctx) (token string, expires time.Time, err error)
func (s *Service) CompleteSetup(ctx, CompleteSetupInput{SetupToken, Username, Password, DisplayName, ClientIP, UserAgent}) (LoginResult, error)
func (s *Service) NewEnrollmentToken(ctx, userID) (token string, expires time.Time, err error)
func (s *Service) RedeemEnrollmentToken(ctx, token, password) (User, error)

// 会话与 MFA
func (s *Service) Login(ctx, LoginInput{Username, Password, ClientIP, UserAgent}) (LoginResult{Session, Token, MFA *MFAChallenge}, error)
func (s *Service) VerifyMFA(ctx, VerifyMFAInput{ChallengeID, Method, Code, ClientIP, UserAgent, SessionToken}) (LoginResult, error)
func (s *Service) AuthenticateSession(ctx, token) (actor.Actor, Session, error)
func (s *Service) Logout(ctx, token) error
func (s *Service) BeginTOTPEnrollment(ctx, userID) (Enrollment{Secret, URL, ExpiresAt, Revision}, error)
func (s *Service) EnableTOTP(ctx, tx, EnableTOTPInput{UserID, ExpectedRevision, Code, Actor}) (recoveryCodes []string, User, error)
func (s *Service) DisableTOTP(ctx, tx, DisableTOTPInput{UserID, ExpectedRevision, Method, Code, Actor}) (User, error)

// 恢复
func (s *Service) ResetAdmin(ctx, ResetAdminInput{Username, Password, Reason}) (User, error)

// 类型
type User{ID, Username, DisplayName, Role, Disabled, MFAEnabled, CreatedAt, UpdatedAt, Revision}
type Session{ID, User, CSRF, MFAVerifiedAt, CreatedAt, LastSeenAt, IdleExpiresAt, ExpiresAt, ClientIP, UserAgent}
type LoginResult{Session, Token, MFA}；func (r LoginResult) Authenticated() bool
type MFAChallenge{ID, Methods, ExpiresAt}
type Role string；RoleAdmin/RoleOperator/RoleViewer；RoleReadonly = RoleViewer
const SessionCookieName = "__Secure-qwq_session"

// 口令/TOTP/退避
func NewHasher(Params, concurrency int) *Hasher；func DefaultParams() Params
func (h *Hasher) Hash(ctx, password) (string, error)
func (h *Hasher) Verify(ctx, encoded, password) (VerifyResult{OK, NeedsRehash}, error)
func (h *Hasher) DummyVerify(ctx) error
func NormalizeUsername(string) (string, error)；func ParseRole(string) (Role, error)
func NewTOTPSecret() ([]byte, error)
func TOTPStep(time.Time) int64；func TOTPCode(secret []byte, step int64) string
func VerifyTOTP(secret, code, now, minStep int64) (step int64, ok bool)
func TOTPURL(issuer, account string, secret []byte) string
func RecoveryCodeHash(code string) string；const RecoveryCodeCount = 10
func NewLoginThrottle(now func() time.Time, ThrottleOptions) *LoginThrottle
func (t *LoginThrottle) Check(account, ip) (time.Duration, bool) / Attempt（原子检查并预扣）/ Fail / Reset / Len

// 协作接口
type SecretSealer interface{ Seal(ctx, purpose string, plaintext []byte) (ref string, err error); Open(ctx, ref string) ([]byte, error) }
type Auditor interface{ Audit(ctx, tx *storage.Tx, rec AuditRecord) error }
type AuditRecord{Action, Actor, Subject, Outcome, Reason, ClientIP, UserAgent, Detail map[string]string, At}
```

### 3.1 调用约定（重要）

1. **哈希在事务外**：`CreateUser`/`ResetPassword` 接收 `PasswordHash`，用 `PreparePassword` 先算好再开事务；argon2 约 40–60 ms，不能占着写锁（ADR-0008 §3）。
2. 写函数都要求 `ExpectedRevision > 0` 且等于当前 revision，否则 `REVISION_CONFLICT` + `current_revision`；缺失/0 返回 `VALIDATION_FAILED`。
3. 每次写资源都在同一事务里 `tx.Changed(...)` 并把返回的 seq 写回行内 `revision`；事件 subject 为 `users/<id>`。
4. 用户 CRUD 的审计由 identity 写（`user.created/updated/deleted/password_reset`）；operations 包另写自己的 operation 审计行，两者 action 不同，不冲突。
5. 认证流程（登录/登出/MFA/session touch）只写审计，不创建 operation（ADR-0008 §2）；它们自己开事务，**不要在调用方的 tx 内调用**。
6. `Login` 返回 `MFA != nil` 时表示需要第二步（OpenAPI 200 + `MfaChallenge`）；否则 `Token` 非空（201 + Set-Cookie）。`CompleteSetup` 同样返回 `LoginResult`。

## 4. authz 导出 API（集成用）

```go
type Permission string
func ParsePermission(string) (Permission, error)；Resource()/Action()/Valid()
type Pattern string；func (p Pattern) Matches(Permission) bool   // "*" 或整段通配
type Resource{Name, NodeID string}
type Role string；RoleAdmin/RoleOperator/RoleViewer；func RoleAllows(Role, Permission) bool；UnknownRole(string) bool
func ParseRole(string) (Role, error)

type PrincipalSource interface{ PrincipalRole(ctx, userID) (role string, disabled bool, err error) }
type Options struct{ DB *storage.DB; Clock clock.Clock; Logger *slog.Logger; Principals PrincipalSource; RateLimiter *RateLimiter; TouchInterval time.Duration }
func New(Options) (*Authorizer, error)
func (z *Authorizer) Authorize(ctx, actor.Actor, permission string, Resource) error
func (z *Authorizer) CanApprove(actor.Actor) bool            // == a.IsHumanSession()
func (z *Authorizer) CanManagePrincipals(actor.Actor) bool   // == a.IsHumanSession()

// 委托
type Delegation{ID, Label, OwnerID, Policy, Status, TokenPrefix, CreatedBy, CreatedAt, UpdatedAt, ExpiresAt, LastUsedAt, Revision}
func (d Delegation) StatusAt(now) Status；Subject()
type Created{Delegation; Token string}
func (z *Authorizer) CreateDelegation(ctx, tx, CreateDelegationInput{Actor, Label, Policy, TTL}) (Created, error)
func (z *Authorizer) UpdateDelegation(ctx, tx, UpdateDelegationInput{Actor, DelegationID, ExpectedRevision, Status *Status, Policy *Policy}) (Delegation, error)
func (z *Authorizer) RevokeDelegation(ctx, tx, RevokeDelegationInput{Actor, DelegationID, ExpectedRevision}) error
func (z *Authorizer) RevokeDelegationsOf(ctx, ownerID) (int, error)   // 自带事务，qwq recover 用
func (z *Authorizer) Delegation(ctx, id) (Delegation, error)
func (z *Authorizer) ListDelegations(ctx, ListDelegationsInput{OwnerID, After, Limit}) ([]Delegation, error)
func (z *Authorizer) AuthenticateBearer(ctx, token string) (actor.Actor, error)

// 服务账号
type ServiceAccount{ID, Name, Role, TokenPrefix, Disabled, CreatedBy, CreatedAt, UpdatedAt, LastUsedAt, Revision}
func (z *Authorizer) CreateServiceAccount(ctx, tx, CreateServiceAccountInput{Actor, Name, Role}) (CreatedServiceAccount{ServiceAccount; Token}, error)
func (z *Authorizer) RevokeServiceAccount(ctx, tx, RevokeServiceAccountInput{Actor, ServiceAccountID, ExpectedRevision}) error
func (z *Authorizer) ServiceAccount(ctx, id) (ServiceAccount, error)
func (z *Authorizer) ListServiceAccounts(ctx, limit) ([]ServiceAccount, error)

// 策略
type Policy{Actions []string, NodeIDs []string, AutoApproveMaxRisk string, OnApprovalRequired string, RequestsPerMinute int32}
func DefaultPolicy() Policy；Normalized()、Validate()、AllowsAction(id)、AllowsNode(id)、Covers(other) error
type Risk string（none/low/medium/high）；type Status string（active/suspended/expired）
type RateLimiter；NewRateLimiter(max int, now func() time.Time) *RateLimiter；Allow(key, perMinute) (bool, time.Duration)
```

### 4.1 鉴权语义

| 调用者 | 有效权限 |
|---|---|
| `system` | 全部放行（宿主内部组件，如 reconciler） |
| `human` | 当前角色授予的权限；角色每请求从 `PrincipalSource` 读取 |
| `service` | 服务账号角色授予的权限 − 人类专属动作 |
| `ai_agent` | 委托人**当前**角色授予的权限 ∩ 委托策略（动作白名单 + 节点范围 + 未暂停未过期）− 人类专属动作；同时消耗速率预算 |

- **人类专属**（ADR-0004 D6）：`host.users:*`、`host.delegations:*`、`host.service_accounts:*`、`host.approvals:*` 以及任何 `*:approve`/`*:reject`。非人类 actor 一定 `PERMISSION_DENIED`，`CanApprove` 永远为 false。
- 暂停/过期的委托：`AuthenticateBearer` 与 `Authorize` 都返回 `PERMISSION_DENIED`（不是 401）。
- 委托 token 被撤销/删除：`AuthenticateBearer` → `UNAUTHENTICATED`；用旧 actor 直接 `Authorize` → `PERMISSION_DENIED`。
- 角色映射（`internal/authz/roles.go`）：admin 全放行；operator 除上述人类管理资源外全放行；viewer 只允许读类动作 `read/list/get/export/describe/watch`。未知角色一律拒绝（fail closed）。
- 通配是**整段**匹配：`host.users:*` 匹配动作，`host.*:create` 不匹配 `host.users:create`（防止手滑放大授权）。委托策略里的 action 模式按 `/` 分段，`*` 匹配一段（与 OpenAPI 的 `com.example.monitor/*` 一致）。
- **策略只能收窄**：`UpdateDelegation` 用 `Policy.Covers` 校验 actions/node_ids/速率/自动批准风险/approval 行为，放宽返回 `VALIDATION_FAILED`。

### 4.2 `Authorize` 的 `Resource`

`Resource.Name` 若非空必须等于权限的 resource 部分（防止拼错），`NodeID` 用于委托的节点范围检查；host 级资源留空。`Action` 是目录动作 ID（如 `host.users.update`、`com.example.monitor/scan.run`）：委托策略列了 `actions` 时必须匹配其中一个模式，未携带 `Action` 的委托检查一律拒绝（fail closed）；operations 的授权适配器总会填它。插件 capability 是**第三道**独立检查，由插件运行时做（ARCH §10.3），本包不代替。

## 5. 默认参数与理由

| 参数 | 默认值 | 理由 |
|---|---|---|
| argon2id | m=19456 KiB (19 MiB), t=2, p=1, salt 16 B, key 32 B | OWASP 内存受限推荐档；两路并发峰值 ≤38 MiB，1 vCPU 单次约 40–60 ms，登录无可感停顿 |
| 哈希并发信号量 | 2 | 与 1C1G 的 30–40 MiB 常驻预算相容；`Hasher` 是进程级共享实例 |
| 口令策略 | 12–256 字符；≥3 类字符或 ≥20 字符口令短语；拒绝 <3 字符用户名包含、常见口令、单字符重复 | 与 OpenAPI `Password` minLength 12 一致；兼顾口令短语 |
| 会话 token | 32 字节 → base64url 43 字符，库中仅 SHA-256 | 256 位熵；DB 泄露不可直接重放 |
| CSRF token | 每会话 32 字节，随 `Session.csrf_token` 返回 | 同步器 token；网关做 Origin/Sec-Fetch-Site 二次校验 |
| 空闲超时 | 30 分钟 | 浏览器面板的常规无操作窗口；每次请求节流刷新 |
| 绝对超时 | 12 小时 | 一天一班；到期强制重新登录（轮换时继承原绝对期限） |
| last_seen 写入节流 | 1 分钟/会话 | 单写连接，避免高刷 UI 打满写锁 |
| 初始化 token TTL | 24 小时；重新生成使旧的作废 | 安装当天可用，过期需重新执行安装步骤 |
| 注册（enroll）token TTL | 24 小时 | 管理员交付链接的合理窗口 |
| MFA 挑战 TTL | 5 分钟，单次使用，最多 5 次错误 | 与 OpenAPI 描述一致 |
| TOTP 注册 TTL | 15 分钟（未确认密钥过期） | 避免遗留未确认 secret |
| MFA 新鲜期 | 15 分钟（`actor.Actor.MFA`） | 与批准默认 15 分钟过期对齐（ADR-0004 D6） |
| 登录退避 | 账号 + 来源：前 2 次失败无延迟，第 3 次 1 s，之后每次翻倍，上限 5 分钟；来源（IPv4 单地址、IPv6 按 /64 聚合）：同一曲线，阈值 10；账号全局：阈值 30，上限 30 s；窗口 15 分钟；检查与预扣原子完成，完整认证成功才退还（待 MFA 时保留）；上限 4096 项，延迟中的条目不驱逐，表满且无可驱逐项时拒绝 | 渐进退避、不硬锁定（ARCH §4.1.1）；账号全局键只压制分布式爆破，他人无法长时间锁号；4096 项约 0.5 MiB |
| 委托 TTL | 默认 30 天，钳制到 300 s–90 天 | 与 OpenAPI `ttl_seconds` 一致 |
| 委托速率 | 默认 60 次/分钟（令牌桶，容量=每分钟额度） | 与 `DelegationPolicy.requests_per_minute` 默认一致；有界 4096 项 |
| 会话/委托 last_used 节流 | 1 分钟 | 同上，减少写事务 |

## 6. 安全设计要点

- 口令：argon2id PHC 字符串；参数写在 PHC 里，登录成功发现 `NeedsRehash` 就用当前参数重算并在**同一事务**里更新（哈希本身在事务外算）。`Verify` 用 `subtle.ConstantTimeCompare`；解析 PHC 时限制 m/t/p/salt/key 上界，坏数据不会触发巨量内存分配。
- 时序：用户不存在或无口令时调用 `Hasher.DummyVerify`（首次惰性生成假哈希），与真实校验同代价。
- token：会话/挑战/一次性 token 都是 32 字节随机、只存 SHA-256；一次性 token 查找后再常量时间比对哈希；委托/服务账号 token 形如 `qwq_dlg_…`/`qwq_sa_…`，库中只有哈希 + 前 16 字符前缀（`token_prefix`，便于泄露扫描）。比较走 B-tree 精确匹配（256 位随机值，不存在可利用的字节级时序）。
- TOTP：RFC 6238，SHA-1/6 位/30 秒/±1 窗口；`credentials.counter` 记录最近接受的时间片，**同一步骤重放被拒**。密钥经 `SecretSealer.Seal` 存 `sec_…` 引用，绝不落明文。
- 恢复码：10 个，20 位 base32（80 位熵，`XXXX-XXXX-XXXX-XXXX`），只存 SHA-256；使用时删除该行（一次性），输入做去分隔符 + 大写规范化。
- 会话轮换：登录发放新会话；提权（`VerifyMFA` 带 `SessionToken`）撤销旧会话、签发新 token，但保留原绝对期限（`created_at/expires_at` 不变）。
- 撞库防护：账号 + IP 两个维度，成功认证才清零；被节流时返回 `RATE_LIMITED` 且带 `retry_after`（`problem.Error.RetryAfterSec`）。
- 审计：登录成功/失败、MFA 成功/失败、登出、MFA 启用/停用、恢复码使用、用户增删改、口令重置、`ResetAdmin`、初始化完成、初始化 token 签发。失败类审计单独小事务写，写失败只记日志，不把登录变成 500。
- `ResetAdmin`（`qwq recover`）：重置口令、删除 TOTP/待确认密钥/恢复码、撤销全部会话、清挑战、写审计（actor=`system:recover`，Reason 记录原因）。它**不删委托**（委托表归 authz）：集成时 `qwq recover` 应再调用 `authz.RevokeDelegationsOf(ownerID)`，避免被盗 token 存活。

## 7. 与 OpenAPI 的对应与不一致

已对齐：

- `POST /api/v1/setup`：`SetupStatus.initialized`；成功后 201 + Set-Cookie；已初始化 409 `STATE_CONFLICT`；错误/已用/过期 token 401 `UNAUTHENTICATED`；`setup_token` 12–? 实际上 43 字符满足 32–128。
- `POST /api/v1/sessions`：无 MFA → 201（`Session` + cookie）；有 MFA → 200（`MfaChallenge`）；失败一律 401 不区分原因；429 + `retry_after`。
- `POST /api/v1/sessions/mfa`：`challenge_id`/`method`/`code`，201 返回 `Session`；挑战单次、5 分钟过期；失败节流。
- `GET /api/v1/sessions/current`：`Session` 含 `csrf_token`、`mfa_verified_at`、`idle_expires_at`、`expires_at`（网关用 `AuthenticateSession`）。
- `DELETE /api/v1/sessions/current`：撤销会话，重复调用无害。
- `User`：`user_id/username/display_name/role/mfa_enabled/disabled/created_at/updated_at/revision` 全部可得；`mfa_enabled` 由 TOTP 凭据推导。
- `UserUpdateRequest`：`expected_revision` 必填、缺席字段不变；停用会撤销会话；删除/降级最后一个管理员 → 409 `STATE_CONFLICT`（OpenAPI 只说删除，更新也一并保护）。
- `Delegation`/`DelegationPolicy`/`DelegationCreateRequest`/`DelegationUpdateRequest`：字段与默认值一致；`token` 只在创建响应出现；停用/恢复/收窄；撤销即删除（token 立刻失效）。
- `Role` 值采用 OpenAPI 的 `admin/operator/viewer`。

不一致（需要主会话裁决/记录）：

1. **只读角色命名**：任务描述与 ADR-0005 写 "readonly"，OpenAPI `Role` 枚举是 `viewer`。本实现以 OpenAPI 为准（`RoleViewer = "viewer"`，另给别名 `RoleReadonly = RoleViewer`）。若产品文案要 "readonly"，需改 OpenAPI 与两处常量。
2. **OpenAPI 缺路由**：TOTP 注册/停用、恢复码展示、口令修改、注册（enrollment）链接兑换都没有对应 path；本包已提供稳定 Go API（`BeginTOTPEnrollment/EnableTOTP/DisableTOTP`、`NewEnrollmentToken/RedeemEnrollmentToken`）。`UserCreateRequest` 描述里的 "one-time enrollment link" 目前由 `CreateUserResult.EnrollmentToken` 提供，但无 HTTP 入口。
3. **服务账号**：OpenAPI 的 `/api/v1/users*` 把 `serviceAccountToken` 列为可用安全方案，但 ADR-0004 D6 与本任务要求"服务账号永远不能管理用户"。本实现按 ADR 执行（`host.users:*` 对人类专属，服务账号一律 `PERMISSION_DENIED`），OpenAPI 的安全方案声明应视为待修正。
4. **服务账号签发**：OpenAPI 明说 out of scope；本包提供 Go 层 `CreateServiceAccount`，无 HTTP 路由；`Subject` 采用 `service_accounts/<id>`（OpenAPI 的 Subject 文档未列该前缀）。
5. **委托 token 前缀**：OpenAPI 只写 `qwq_dlg_...`；本实现 `token_prefix` 取前 16 字符（含 `qwq_dlg_`），符合 `maxLength: 16`。
6. **`last_used_at` 不产生 revision**：它是状态信息而非资源修改，更新时不发 `resource.changed`、不加 revision；否则每次 AI 调用都会让 UI 看到"委托被修改"并使 `expected_revision` 失效。
7. **`DelegationPolicy.actions` 的执法层**（AUTH-01 已解决）：OpenAPI 的 actions 是 action ID 模式，而 permission 不含动作 ID。最初只提供 `Policy.AllowsAction(actionID)` 给 agentapi 做展示过滤，执行路径从不检查，白名单形同虚设；现在 `Resource.Action` 携带动作 ID，`Authorize` 对委托直接执行白名单检查。插件 capability 仍由运行时检查。
8. **`MFA_REQUIRED` 未使用**：破坏性批准需要 MFA 时，是否返回 `403 MFA_REQUIRED` 由 operations/网关决定；identity 只报告 `actor.MFA` 的新鲜度。

## 8. 测试

命令（构建机 `/root/qwq-dev/p1a`，`QWQ_REMOTE_SRC=p1a`）：

```bash
GOWORK=off go vet ./internal/identity/... ./internal/authz/...
staticcheck ./internal/identity/... ./internal/authz/...
gofmt -l internal/identity internal/authz
CGO_ENABLED=1 GOWORK=off go test -race -count=1 -cover ./internal/identity/... ./internal/authz/...
```

结果：vet/staticcheck/gofmt 无输出；`ok internal/identity 16.4s coverage 77.5%`、`ok internal/authz 7.1s coverage 71.1%`（均为 `-race`）。

覆盖内容：

- identity：口令策略/PHC 往返/参数升级重算/信号量阻塞/并发哈希/假哈希；RFC 6238 官方向量与 ±1 窗口、重放；用户名规范化；退避曲线、三类键隔离与账号全局上限、原子预扣并发、IPv6 /64 聚合、reset、过期、容量上限与表满拒绝、服务级集成（含并发猜测与待 MFA 保留扣减）；初始化 token（哈希存储、过期、作废旧的、重复调用 409、弱口令校验）；登录/失败不可区分/停用用户；会话空闲与绝对超时、touch 节流、登出幂等；MFA 注册/两步登录/恢复码一次性/挑战次数上限/提权轮换；用户增删改、revision 冲突（含 current_revision）、空补丁不烧 revision、停用撤销会话、最后管理员保护、删除级联、口令重置撤销会话、注册 token 兑换、`PrincipalRole`、分页；`ResetAdmin`（停 MFA、撤会话、新口令可用、审计原因）。
- authz：权限解析/整段通配/角色表/未知角色 fail closed；策略默认值/校验/动作模式/节点/收窄；人类授权矩阵（含停用与未知用户）；委托创建仅限真人会话、`AuthenticateBearer` actor 形状、超出委托人 RBAC 被拒、批准被拒、`CanApprove` 为 false、**委托人降级后权限缩小**、委托人停用后 token 失效；暂停/恢复/过期/撤销；节点范围；速率限制（含 `retry_after` 与时间窗恢复）；策略只能收窄；仅 owner/admin 可管理；服务账号生命周期、角色限制、人类专属拒绝、停用与撤销；创建规则（仅真人、角色/名称校验、唯一）。

## 9. 需要别的包配合 / 未完成

1. `internal/secrets` 实现 `identity.SecretSealer`（purpose 使用 `identity.totp`）。目前 `internal/secrets` 只导出 `KeyRing`、`Ref`（`sec_…`，与 `credentials.secret` 兼容）、`Secret`、AES-GCM 原语，**还没有 `Seal/Open` 高层入口**；适配器需要写在 `internal/secrets` 或 `internal/controller`（两者都不在本任务写入范围）。
2. `internal/operations` 实现 `identity.Auditor`（当前 operations 尚无审计实现，只有文档提及）：按 `AuditRecord` 落表；失败类审计与登录成功审计都在调用方事务内。建议 audit action 用本包常量，避免字符串漂移。
3. `internal/controller` 组装：
   - `identity.New` → `authz.New(Options{Principals: identitySvc})`（`identity.Service.PrincipalRole` 的签名与 `authz.PrincipalSource` 完全一致）。
   - `qwq recover` 组合 `identity.ResetAdmin` + `authz.RevokeDelegationsOf`。
   - **`operations.Authorizer` 适配器**：operations 的接口是 `Authorize(ctx, a, act operations.Action, target operations.Target) error`，本包不接受 `operations.Action`（领域包不互相导入）。适配器把 `act.Permission` 解析成权限串、把 `target.NodeID` 映射为 `authz.Resource{NodeID}` 后转调 `authz.Authorize`。插件动作的 `act.Permission` 可能为空：需要在 catalog/operations 侧明确“空权限”的语义（本包对空串返回 `VALIDATION_FAILED`，不会静默放行）。
   - `operations.Policy`（`Limits(ctx, a, act, target)`）：对 `ai_agent` 取 `authz.Delegation(a.ID).Policy` 的 `AutoApproveMaxRisk`/`OnApprovalRequired`/`RequestsPerMinute` 填 `operations.Limits`；`DelegationPolicy` 没有字段映射到 `Limits.MaxRisk`，需要 operations 决定默认值。
4. 网关需要：Cookie 写入规则（`HttpOnly; Secure; SameSite=Lax; Path=/api/`，名 `identity.SessionCookieName`，过期用 `Session.IdleExpiresAt`/`ExpiresAt` 的较小值）、CSRF 头 `X-CSRF-Token` 与 `Session.CSRF` 比对、`actor.Actor` 注入 context、`/api/v1/agent/*` 只接受委托 token（其它路由拒绝）、Origin/Host 校验。
5. 路由缺口（见 §7 第 2、4 条）：TOTP 管理、注册链接兑换、服务账号签发目前只有 Go API。
6. `expected_revision` 由网关把字符串解析为 int64 后传入（本包用 int64；解析不在本包）。
7. 未实现（明确不在 P1-T3/T4 范围）：WebAuthn/OIDC 的真实校验（表结构已预留）、口令泄露库检查、多节点级授权策略、审批/计划本身（operations）。

