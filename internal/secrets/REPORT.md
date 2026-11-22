# P1-T6（secret 存储）+ P1-T9（TLS）实现报告

范围：`internal/secrets/**`、`internal/tlsmgr/**`、`internal/storage/migrations/0005_secrets.sql`。
未改 `go.mod`/`go.sum`（只用已有 `golang.org/x/crypto` 的 `acme`、`acme/autocert`），未引入新依赖，未改其他包。

## 1. 文件清单

### secrets

| 文件 | 内容 |
|---|---|
| `internal/secrets/secrets.go` | 包文档、`Store`、`Options`、`Put`/`Seal`/`Reveal`/`Open`/`Delete`/`DeleteOwner`/`Rotate`/`KeyUsage`、owner/purpose 校验 |
| `internal/secrets/keys.go` | `Key`、`KeyRing`、`LoadKeyRing`、主密钥原子创建、权限检查、轮换、`DropRetired`、原子写文件 |
| `internal/secrets/cipher.go` | AAD 构造、`seal`/`open`（AES-256-GCM） |
| `internal/secrets/value.go` | `Ref`（`sec_…`）、`Secret`（脱敏明文类型）、`RefObject`/`RefFromObject`（引用 JSON 形态） |
| `internal/secrets/schema.go` | `ExtractSecrets`、`RedactForExport`、`ResolveSecrets`、JSON Schema 遍历器、`SchemaError` |
| `internal/secrets/*_test.go` | 主密钥/权限/轮换、加解密与 AAD、ExtractSecrets、日志脱敏、并发与 `-race` |
| `internal/secrets/REPORT.md` | 本文 |

### tlsmgr

| 文件 | 内容 |
|---|---|
| `internal/tlsmgr/tlsmgr.go` | 包文档、`Options`、`New`、`TLSConfig`、`GetCertificate`、`Fingerprint`、`Reload`、`Maintain`、`Status`/`Ready` |
| `internal/tlsmgr/selfsigned.go` | SAN 集合、ECDSA P-256 自签名生成、持久化与原子写、轮换判定、指纹格式、目录/文件权限收紧 |
| `internal/tlsmgr/acme.go` | autocert 装配、HostPolicy、缓存目录、`HTTPHandler`、从缓存读证书算就绪 |
| `internal/tlsmgr/*_test.go` | 生成/持久化/指纹稳定/SAN/轮换/真实握手与 Reload/ACME 配置/proxy/就绪 |

### 迁移

`internal/storage/migrations/0005_secrets.sql` 替换了占位内容（原为 `SELECT 1;`）。

## 2. secret 存储

### 2.1 主密钥

- 路径 `<data_dir>/keys/master.key`，内容为 32 字节原始随机（**不是** PEM/base64），权限 `0600`；目录 `0700`。
- 权限过宽不修复而是**拒绝启动**，错误里带路径、实际模式与修复命令：
  `secrets: /var/lib/qwq/keys/master.key has mode 0644; the master key must not be accessible by group or others (chmod 600 …)`。
  目录同理（提示 `chmod 700`）。key 文件必须是普通文件（`Lstat`），长度不是 32 字节则报错。
- 首次创建：临时文件（`0600`）→ 写入 → `fsync` → **硬链接到最终名字**（`link(2)` 在目标已存在时返回 `EEXIST`）→ 目录 `fsync`。
  用 link 而不是 rename 的原因：rename 会静默覆盖另一个进程刚创建的主密钥，导致旧密文不可解；link 的“存在即失败”正好是创建语义。轮换写 `master.key` 时用 rename（此时覆盖是目的），同样是 temp+fsync+rename+目录 fsync。
- key id：`sha256(key)` 前 8 字节的小写十六进制（16 字符），存进 `secrets.key_id`；`Key.String`/`GoString`/`LogValue` 只输出 id。
- 多密钥：`keys/retired-<keyid>.key`（`0600`）保存旧密钥，`LoadKeyRing` 全部加载；文件名中的 id 与文件内容不符时拒绝（不猜）。
  `KeyRing.Rotate()` 先写旧密钥的 retired 副本、再替换 `master.key`，任一步崩溃都还能解密已有密文。
  `KeyRing.DropRetired(id)` 在确认没有行再用它之后删除文件（`Store.KeyUsage` 给出每个 key 的行数）。
- AEAD 缓存：每个 key 的 `cipher.AEAD` 在加载/轮换时构建一次，读路径无锁竞争（`RWMutex` 只保护 map 与 primary）。

### 2.2 表（0005）

```sql
CREATE TABLE secrets (
    id         TEXT    NOT NULL PRIMARY KEY,  -- sec_<UUIDv7 base32>
    owner      TEXT    NOT NULL,              -- users/usr_…, plugins/<id>/instances/<id>, config, system
    purpose    TEXT    NOT NULL,              -- identity.totp, plugin.config, …
    key_id     TEXT    NOT NULL,              -- 主密钥 id（16 hex）
    nonce      BLOB    NOT NULL,              -- 12 字节随机
    ciphertext BLOB    NOT NULL,              -- 含 GCM tag
    created_at TEXT    NOT NULL,              -- RFC 3339 UTC 毫秒（storage.TimeFormat）
    revision   INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX secrets_owner_idx ON secrets (owner);
CREATE INDEX secrets_key_idx   ON secrets (key_id);
```

- `revision` 目前恒为 0 且**有意的**：secret 不发布 `resource.changed`（ARCH §5.6 要求 secret 不进事件；公共 API 也没有 secret 资源），因此没有事件序号可记。列保留是为了与其他可变资源表的结构一致，将来若增加 secret 元数据事件再填。
- `owner` 是“谁拥有这行”，用于卸载清理；`purpose` 是“这行能做什么用”，参与 AAD 与 `Reveal` 校验。两者字符集：字母数字与 `_ - . :`，owner 另允许 `/`（不得以 `/` 开头、不得有 `//`）；owner ≤512 字节，purpose ≤128 字节。
- 单值上限 1 MiB（`MaxPlaintext`），与请求体上限同量级；配置整体可包含多个值。

### 2.3 加密与 AAD

- AES-256-GCM，12 字节随机 nonce（`crypto/rand`），密文含 tag。
- AAD = `"qwq.secret.v1"` + 依次对 `(id, owner, purpose)` 写 `uint32 大端长度 + 原始字节`。
  长度前缀让编码是单射（字段里出现分隔符也不会歧义），因此把密文换到别的行、改 owner、改 purpose 都过不了认证。
- 失败映射（`internal/platform/problem`）：
  - 行不存在 → `NOT_FOUND`；引用格式非法/参数非法 → `VALIDATION_FAILED`；
  - `Reveal` 的 purpose 不匹配 → `PERMISSION_DENIED`（“The secret is not available for this purpose.”）；
  - 认证失败（篡改/换行/错密钥）、key 不在环里、SQL/IO 错误 → `INTERNAL`（`Cause` 写日志，`Detail` 不外泄；错误文本只有 ref，绝无明文）。
- 轮换 `Store.Rotate(ctx, batch)`：每批一个写事务，`SELECT … WHERE key_id <> 主 key ORDER BY id LIMIT batch`，读出后在内存解密、用新 key 重加密、`UPDATE` 回同一行（id/owner/purpose 不变，所以 AAD 不变）。返回重写行数。
  运维顺序：`KeyRing.Rotate()` → `Store.Rotate(ctx, n)` → `Store.KeyUsage` 确认旧 key 为 0 行 → `KeyRing.DropRetired(oldID)`。

### 2.4 导出 API

```go
// 主密钥
func LoadKeyRing(dataDir string) (*KeyRing, error)
func (r *KeyRing) Dir() string
func (r *KeyRing) Primary() Key
func (r *KeyRing) IDs() []string           // primary 在前，其余排序
func (r *KeyRing) Retired() []string
func (r *KeyRing) Rotate() (Key, error)
func (r *KeyRing) DropRetired(id string) error
type Key struct{ ID string /* 私有 32 字节 */ }
func (k Key) String() string; func (k Key) GoString() string
func (k Key) LogValue() slog.Value         // 只输出 key id

// 存储
type Options struct{ DB *storage.DB; Keys *KeyRing; Logger *slog.Logger }
func New(o Options) (*Store, error)
func (s *Store) Keys() *KeyRing
func (s *Store) Put(ctx context.Context, tx *storage.Tx, owner, purpose string, plaintext []byte) (Ref, error)
func (s *Store) Seal(ctx context.Context, purpose string, plaintext []byte) (string, error)   // identity.SecretSealer 形态
func (s *Store) Reveal(ctx context.Context, ref Ref, purpose string) (Secret, error)
func (s *Store) Open(ctx context.Context, ref string) ([]byte, error)                        // identity.SecretSealer 形态
func (s *Store) Delete(ctx context.Context, tx *storage.Tx, ref Ref) error
func (s *Store) DeleteOwner(ctx context.Context, tx *storage.Tx, owner string) (int64, error)
func (s *Store) Rotate(ctx context.Context, batch int) (int64, error)
func (s *Store) KeyUsage(ctx context.Context) (map[string]int64, error)

// 引用与明文
type Ref string
func ParseRef(s string) (Ref, error)
func (r Ref) String() string
func (r Ref) Valid() bool
func RefObject(r Ref) map[string]any
func RefFromObject(v any) (Ref, bool)
type Secret struct{ /* 私有 bytes */ }
func (s Secret) Bytes() []byte; func (s Secret) Len() int; func (s Secret) IsEmpty() bool
func (s *Secret) Clear()
func (s Secret) String() string; func (s Secret) GoString() string
func (s Secret) LogValue() slog.Value
func (s Secret) MarshalJSON() ([]byte, error)   // 永远返回错误，防止误序列化

// 配置中的敏感字段
type ExtractOptions struct{ Owner, Purpose string }
type Extracted struct{ Pointer string /* RFC 6901 */; Ref Ref; Purpose string }
func (s *Store) ExtractSecrets(ctx context.Context, schema, config []byte, opts ExtractOptions) ([]byte, []Extracted, error)
func (s *Store) ResolveSecrets(ctx context.Context, config []byte) ([]byte, error)
func RedactForExport(schema, config []byte) ([]byte, error)
type SchemaError struct{ Pointer, Keyword, Reason string }
```

`ExtractSecrets` 需要 ctx 与 owner（拆配置的调用方知道实例归属），所以是 `Store` 的方法并带 `ExtractOptions`；这与任务里 `ExtractSecrets(schema, config)` 的形态相比多两个参数，是为了让 `DeleteOwner` 能在卸载时清理。

事务边界：`Put`/`Delete`/`DeleteOwner` 用调用方给的 `storage.Tx`（与资源行同一事务提交，回滚一起消失）；`Seal`/`ExtractSecrets`/`Rotate` 自己开写事务，**不能**在另一个写事务里调用（宿主只有一个写连接，嵌套会死锁）；`Reveal`/`Open`/`KeyUsage`/`ResolveSecrets` 走只读连接，可随时调用。

### 2.5 secret 引用 JSON 形态

敏感值被替换成**只含一个成员的对象**：

```json
{"$secret": "sec_01j9z6m2t4v6x8y0a2b4c6d8e0"}
```

- 常量为 `secrets.RefKey = "$secret"`；`RefObject`/`RefFromObject` 负责构造与识别。
- 引用本身可安全进日志、事件、审计、导出；`ResolveSecrets` 在应用配置前把它逐一换回原值（`Store.Open`），是 `ExtractSecrets` 的逆操作（值以 JSON 编码保存，所以字符串/数字/对象/数组原样还原）。
- `RedactForExport` 不产生引用，直接把值换成字符串 `"[REDACTED]"`（与日志脱敏同一个常量），供配置历史、导出、显示使用；整个文档被标记为敏感时输出就是 `"[REDACTED]"`。

### 2.6 ExtractSecrets 的 schema 支持

只用标准库：`encoding/json`（`UseNumber`）把 schema 与配置解码成 `any` 后，**并行遍历** schema 与实例，收集“要替换的实例 JSON Pointer 集合”，再一次性在**一个写事务**里加密所有值（要么全有引用，要么全没有），最后重写文档。结果按 pointer 排序，输出确定。

判定：某个 schema 节点 `writeOnly: true` 或 `x-secret: true` → 该节点**对应的整个值**（可以是对象/数组）被替换。

支持的关键字：

| 关键字 | 行为 |
|---|---|
| `properties` | 按成员名匹配实例 |
| `items` | 数组元素；与 `prefixItems` 同时出现时只作用于前缀之后的元素 |
| `prefixItems` | 按索引匹配 |
| `additionalProperties` | 只作用于未在 `properties` 声明且实际存在的成员 |
| `allOf` / `anyOf` / `oneOf` | 每个分支都遍历；**任一分支**声明敏感即敏感（宁可多redact，不可漏） |
| `$ref` | 只解析同文档本地引用（`#`、`#/$defs/…` 等任何 `#/` 指针），支持 `$ref` 与兄弟关键字并存（2020-12 语义），按 `(ref, 实例 pointer)` 去重以避免递归 schema 死循环 |
| 布尔 schema | `true`/`false` 不声明敏感，直接跳过 |

**fail-closed** 的（出现即报 `SchemaError`，由调用方转成 `VALIDATION_FAILED`，`Cause` 里带关键字与 schema pointer）：

- `patternProperties`、`dependentSchemas`、`propertyNames`、`if`/`then`/`else`、`not`、`contains`、`unevaluatedProperties`、`unevaluatedItems`、`$dynamicRef`；
- 非本地 `$ref`（`https://…`）、解析不到的 `$ref`；
- `writeOnly`/`x-secret` 不是布尔、`properties`/`items`/`prefixItems`/`additionalProperties` 类型不对；
- schema 嵌套超过 64 层（manifest 允许 64 层，见 ARCH §5.3）。

已知取舍：

- **未声明的成员原样保留**：schema 没声明（且 `additionalProperties` 不是 schema）的成员，宿主无从判断是否敏感，只能按“已声明契约”处理；这类配置应由插件用 `additionalProperties: false` 或完整声明来收紧。这是文档化的限制，不是静默放过不支持的关键字。
- 输出由 `encoding/json` 重新编码，对象键会按字典序排列、数字用 `json.Number` 保留精度（不会经 float64 丢位）。引用/导出文档与原文的键顺序可能不同。

### 2.7 日志

- `Secret` 实现 `slog.LogValuer`、`fmt.Stringer`、`fmt.GoStringer`（`%#v` 也不泄露）、`MarshalJSON`（永远报错）；`Key` 的三种字符串形态只输出 id。
- `Store` 只记引用与元数据：`secret stored`（ref/owner/purpose/key_id）、`secret deleted`、`secrets deleted with their owner`、`secret fields extracted from config`、`secret key rotation finished`；全部 Debug/Info 级，绝无明文。
- 测试用 `internal/platform/logging` 的 JSON handler 跑完整流程（Put/Seal/Reveal/Open/轮换/Delete），断言输出含 `sec_`、含 `[REDACTED]`、不含 canary 明文。

## 3. TLS 管理

### 3.1 入口

```go
type Options struct {
    TLS config.TLS               // Mode/Domains/Email/DirectoryURL
    Listen string                // 管理监听 host:port（决定自签名 SAN）
    PublicOrigins []string       // config.HTTP.PublicOrigins
    DataDir string
    Clock clock.Clock
    Logger *slog.Logger
    CheckEvery time.Duration     // 维护间隔（默认 6h，测试可缩短）
    LocalAddrs func() ([]net.Addr, error) // 枚举本机地址（测试注入）
}
func New(o Options) (*Manager, error)
func (m *Manager) Mode() string
func (m *Manager) TLSConfig() *tls.Config                  // proxy 模式返回 nil
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
func (m *Manager) Fingerprint() string                     // 自签名/已加载证书
func (m *Manager) Reload() error                           // 从磁盘热替换
func (m *Manager) Maintain(ctx context.Context)            // 定期检查/轮换/告警，直到 ctx 结束
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler
func (m *Manager) Status(ctx context.Context) Status
func (m *Manager) Ready(ctx context.Context) error         // Status(ctx).Err()
type Status struct{ Mode string; Ready, Warn bool; NotAfter time.Time; ExpiresIn time.Duration; Fingerprint, Detail string }
func (s Status) Err() error                                // Ready 时 nil，否则 UNAVAILABLE
```

### 3.2 self_signed

- ECDSA P-256，自签名，`IsCA=true` + `KeyUsageCertSign`（这样客户端可以把证书本身 pin 成根做校验；Go 的 `crypto/tls` 生成工具也是这么做的），`ExtKeyUsage=ServerAuth`。
- 有效期 397 天（低于浏览器接受的 398 天上限），`NotBefore = now-1h` 容忍客户端时钟偏慢。
- 文件：`<data_dir>/tls/self_signed.crt`（`0644`）、`self_signed.key`（`0600`），目录 `0700`；全部 temp+fsync+rename+目录 fsync，先写 key 再写 crt（中途崩溃留下不匹配 → 下次启动判为不可用并重新生成）。目录/密钥权限过宽时自动收紧到 `0700`/`0600` 并 Warn（不是主密钥那种“拒绝启动”，因为这里丢了可以重生成）。
- SAN：监听 host（`0.0.0.0`/`::` 时枚举本机地址）、`localhost`、`127.0.0.1`、`::1`、`public_origins` 的 host（host 是 IP 就进 IP SAN，否则进 DNS SAN，统一小写、去尾点）。
  枚举时跳过回环/未指定/组播/**link-local**：link-local 浏览器用不到，且会随 DHCP/MAC 变化，包含进来只会让证书与指纹无谓地轮换。
- 轮换：启动时与 `Maintain` 每 `CheckEvery`（默认 6h）检查一次；剩余 < 30 天、或现有证书不再覆盖当前配置的 SAN、或文件缺失/损坏/公私钥不匹配 → 重新生成。
  **指纹稳定**：配置不变时重复启动读取同一份文件，指纹不变（测试覆盖）；只有配置里的地址/域名真的变了才会变。
- `Fingerprint()`：证书 DER 的 SHA-256，冒号分隔大写十六进制（`AB:CD:…`，95 字符），与 `SetupStatus.tls_fingerprint`（maxLength 128）和浏览器展示一致。
- `Reload()`：重新读盘、校验后原子换指针；已建立连接不受影响（测试：Reload 后旧连接继续收发，新连接用新证书）。

### 3.3 TLS 参数与理由

| 项 | 值 | 理由 |
|---|---|---|
| `MinVersion` | TLS 1.2 | TLS 1.0/1.1 已被主流浏览器禁用且不安全；1.2 是自托管环境现实的下限，1.3 自动优先协商 |
| `CipherSuites` | ECDHE + AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305（ECDSA 与 RSA 各一套，共 6 个） | 全部 AEAD + 前向保密；无 CBC/RC4/3DES/静态 RSA。AES-GCM 在有 AES-NI 的 x86 上最快，ChaCha20 照顾没有 AES 加速的 ARM 小机器。TLS 1.3 的套件由 Go 内置、不在此列 |
| `CurvePreferences` | X25519, P-256, P-384 | X25519 最快且常量时间；P-256/P-384 兼容老客户端与 FIPS 倾向的环境 |
| `NextProtos` | `h2`, `http/1.1`（acme 模式再加 `acme-tls/1`） | HTTP/2 是面板（SSE 多、请求碎）的主要收益；ALPN 里带 `h2` 才能让 `http.Server` 自动启用 HTTP/2；ACME 模式必须声明 `acme-tls/1` 才能答 TLS-ALPN-01 |
| `GetCertificate` | 读 `atomic.Pointer[cert]` | 热替换无锁；`Reload`/轮换只换指针，不打断连接 |
| `Renegotiation` | `RenegotiateNever` | 服务端不需要客户端发起的重协商，是已知 DoS 面 |
| 会话票据 | 默认开启 | 面板是少量浏览器长连，票据降低重连成本；密钥随进程 |

### 3.4 acme

- `golang.org/x/crypto/acme/autocert`，缓存 `<data_dir>/acme`（`0700`，过宽自动收紧）；`Prompt=AcceptTOS`、`Email` 取配置、`DirectoryURL` 非空时设置 `acme.Client.DirectoryURL`（可指 staging；留空即 Let's Encrypt 生产）。
- `HostPolicy`：域名在 `New` 时小写、去尾点后放入白名单，**精确匹配**；其他任何 SNI 一律拒绝。防止攻击者把任意域名指到本机骗宿主签发证书（HTTP-01 还会在 80 端口应答）。
- TLS-ALPN-01：`GetCertificate` 直接委托 autocert（测试断言 `NextProtos` 含 `acme-tls/1`）。
- HTTP-01：`HTTPHandler(fallback)` 包装应用 handler，非挑战路径原样透传；需要外网可达的 **80 端口**——**当前测试机上 80/443 由宝塔占用，那里不能用 HTTP-01**，ACME 只能走 TLS-ALPN-01（443）或换机器。
- `New` **不做任何网络请求**（测试同样不连真实 ACME）；首次握手/挑战时才联系目录。autocert 在到期前约 30 天按需续期，所以运行中的宿主只要还有握手就会自动续。
- 就绪：`Status` 从缓存里按域名读证书（`autocert.DirCache.Get`），取最早到期的一张；还没签发过 → 未就绪、Detail 说明“尚未签发”，`/readyz` 应据此返回 503。
- `Fingerprint()` 在 acme 模式返回空（安装输出只在只有 IP 的自签名场景打印指纹）；需要时用 `Status().Fingerprint`。

### 3.5 proxy

- `TLSConfig()` 返回 `nil`：网关自己 `http.ListenAndServe`（明文，只应绑回环）；是否信任 `X-Forwarded-*` 只由 `config.HTTP.TrustedProxies` 决定（`config.Validate` 已强制 proxy 模式必须有受信反代且监听回环）。
- `HTTPHandler` 原样返回 fallback；`Status` 恒为就绪并说明 TLS 由反代终止。

## 4. 执行过的命令与结果

均在 Linux 构建机上、经 `scripts/remote.sh`（`QWQ_REMOTE_SRC=p1c`）、只针对这两个包执行：

| 命令 | 结果 |
|---|---|
| `gofmt -l internal/secrets internal/tlsmgr` | 无输出（已格式化） |
| `go vet ./internal/secrets ./internal/tlsmgr` | 通过 |
| `go test -count=1 ./internal/secrets` | ok（约 0.8s） |
| `go test -count=1 ./internal/tlsmgr` | ok（约 0.2s） |
| `staticcheck ./internal/secrets ./internal/tlsmgr` | 无告警 |
| `CGO_ENABLED=1 go test -race -count=1 ./internal/secrets ./internal/tlsmgr` | ok（约 6.9s / 1.4s） |

测试覆盖（对照任务要求）：

- secrets：`sec_` 往返、purpose 不匹配、篡改密文、换行（AAD 含 id）、改 purpose（AAD）、错密钥（同 id 不同 key）、retired key 丢失、`DeleteOwner` 幂等、参数校验、批量轮换后仍能读旧值、重载 key ring 后仍能读、并发 Seal/Open（race）、行内无明文、日志无明文、主密钥模式/权限/长度/不匹配 retired 文件名、`Key` 脱敏。
- ExtractSecrets：嵌套对象、`$ref`、`additionalProperties`、数组 `items`、`prefixItems`、`allOf`/`oneOf`、递归 `$ref` 环、整文档敏感、无敏感字段、未声明字段、9 种不支持结构的拒绝、坏 JSON、`RedactForExport` 无明文/无引用、`ResolveSecrets` 还原、`RefObject` 形态。
- tlsmgr：证书内容（IsCA/有效期/SAN/指纹格式）、文件与权限、指纹跨重启稳定、30 天内/域名变化时替换、`Maintain` 自动轮换与 ctx 退出、`TLSConfig` 参数、`Status` 就绪/14 天告警/过期、`Reload` 换证书且不断连接、坏 pair 的 Reload 被拒、回环真实 TLS 握手（验证证书 + ALPN=h2 + 双向收发）、ACME（域名规范化、HostPolicy 接受/拒绝、缓存目录权限、DirectoryURL/Email、`acme-tls/1`、HTTPHandler 透传、未签发时未就绪）、proxy（nil config、指纹空、就绪、HTTPHandler 透传）。

## 5. 需要其他包配合的事项

1. **identity 的 `SecretSealer`**：`*secrets.Store` 直接满足 `identity.SecretSealer`（`Seal(ctx, purpose string, plaintext []byte) (string, error)`（`Open(ctx, ref string) ([]byte, error)`），测试里有编译期断言。controller 组装时把 store 传给 `identity.Service.Sealer` 即可，无需适配器。
   注意：`Seal` 所属 owner 固定为 `secrets.SystemOwner`（`"system"`），因为该接口不带 owner。identity 删除用户/凭证时不会删对应 secret 行 → 会留下“孤儿”密文（读不出明文，只占空间，且 key 轮换会重写它）。建议主会话二选一：让 identity 在删除凭证时把 ref 交给 controller，由 controller 在事务里 `secrets.Delete`；或后续给 identity 加一个 `SecretRefs`/删除钩子（需要改 identity 的导出 API，不在本任务范围）。用带 owner 的 `Put` 的场景（插件实例配置）没有这个问题。
2. **配置敏感字段的接入点**：保存 config 快照时用 `ExtractSecrets(ctx, schema, config, ExtractOptions{Owner: "plugins/<id>/instances/<inst>", Purpose: "plugin.config"})`，把引用写进快照；应用前 `ResolveSecrets`；配置历史/导出/日志用 `RedactForExport`。schema 里出现不支持的关键字会让安装失败（fail-closed，`Cause` 是 `*secrets.SchemaError`），安装向导应把 cause 记进日志/诊断。
3. **gateway**：`http.Server.TLSConfig = m.TLSConfig()`（或 `ServeTLS` 用同一份），需要 HTTP/2 时确保 `NextProtos` 原样保留；`m.HTTPHandler` 用于 80 端口的 HTTP-01（只有 acme 且 80 可用时才需要）；`/readyz` 用 `m.Ready(ctx)`（或 `Status(ctx)` 拿 `Warn`/`Detail`），`/healthz` 不要碰证书检查；`Reload`/`Status` 是并发安全的。
4. **controller**：启动时 `secrets.LoadKeyRing(cfg.DataDir)` → `secrets.New` → 一个 goroutine 跑 `tlsmgr.Maintain(ctx)`；安装输出用 `Fingerprint()`（仅 self_signed；`SetupStatus.tls_fingerprint` 直接放它）。
5. **安装器/文档**：`data_dir/keys` 必须 `0700`、`master.key` `0600`，否则宿主拒绝启动（这是有意的，不要“帮用户修”）；备份时数据库与 `keys/` 必须**分开加密备份**（ARCH §8.3），丢了主密钥等于所有 secret 永久作废。`data_dir/tls` 与 `data_dir/acme` 同样只给宿主用户读。
6. **轮换 SOP**（可写进运维文档）：`KeyRing.Rotate()` → `Store.Rotate(ctx, batch)` → `Store.KeyUsage` 确认旧 key 0 行 → `KeyRing.DropRetired(oldID)`；轮换期间新旧值都可读。
7. **没有改动**：`go.mod`/`go.sum`、`internal/storage`（只替换了 0005 占位）、`api/`、`docs/`、`scripts/`，以及其他子代理的包。
