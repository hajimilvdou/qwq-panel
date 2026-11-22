# P2-T3 插件打包、签名、校验与安装解包

本文是 P2-T3 的详细报告。摘要见提交说明与最终回复；本文件记录格式规范、导出 API、资源上限的取值理由、验证命令与结果，以及与其他任务的接口约定。

任务对应 `IMPLEMENTATION-PLAN.md` P2-T3：`qwqctl pack/sign/verify`；安装器：验签 → 严格解析 → 校验 → `os.Root` 解包 → 摘要 → 原子 rename，归 root 只读。架构依据 `docs/ARCHITECTURE.md` §5.1（包结构与 `manifest.sig` 信封）、§5.3（manifest 规则）、§6.2（安装顺序）、§10.4（供应链与 decompression bomb）。

## 1. 交付文件

| 文件 | 行数 | 内容 |
|---|---|---|
| `sdk/pkgfile/pkgfile.go` | 243 | 包注释中的**格式规范**、`Limits`/`DefaultLimits`、`Package`/`FileInfo`/`Sink`/`ReadOptions` |
| `sdk/pkgfile/errors.go` | 159 | `Violation`/`Error`（结构化 code，风格同 `sdk/manifest`）、全部 code 常量 |
| `sdk/pkgfile/pack.go` | 529 | 确定性 tar+gzip 写入器、`Pack`、源目录遍历、manifest 重写与严格解码 |
| `sdk/pkgfile/read.go` | 505 | `Read`/`ReadUnverified`、先验签后读、路径/类型/权限校验、预算与压缩比 |
| `sdk/pkgfile/sign.go` | 281 | `Sign`/`Resign`、PKCS#8/PKIX PEM 编解码、`DigestFile`/`VerifyFile` |
| `sdk/pkgfile/*_test.go` | 1453 | 打包/读取/签名/限额/压缩炸弹/重签/`FuzzRead` |
| `internal/pluginhost/install/install.go` | 460 | `Extract`/`Staged`/`Commit`/`Discard`/`CleanupStale`/`VersionDir` |
| `internal/pluginhost/install/owner_unix.go` | 42 | root 归属断言（`//go:build unix`，非 root 跳过） |
| `internal/pluginhost/install/owner_other.go` | 9 | 非 unix 空实现 |
| `internal/pluginhost/install/install_test.go` | 678 | 全流程、各类坏包、压缩炸弹、重复安装、崩溃残留清理 |
| `cmd/qwqctl/main.go` | 60 | 命令分发与总帮助（保留 `version`/`help` 行为） |
| `cmd/qwqctl/plugin.go` | 376 | `keygen`/`pack`/`sign`/`verify` |
| `cmd/qwqctl/plugin_test.go` | 263 | `t.TempDir()` 中 keygen → pack → verify → sign 全流程与用法错误 |

`cmd/qwqctl/main_test.go` 未改动，原有 `version`/`help`/未知命令用例继续通过。

许可：`sdk/pkgfile/**` 为 `Apache-2.0`（第三方工具可直接复用）；`internal/pluginhost/install/**`、`cmd/qwqctl/**` 为 `AGPL-3.0-only`。未新增任何依赖（`go.mod`/`go.sum`/`sdk/go.mod` 未改）；`sdk/pkgfile` 仅依赖标准库与 `sdk/manifest`。

## 2. 包格式规范（`.ppkg`）

### 2.1 容器

gzip（RFC 1952）包裹 USTAR tar。第三方工具用 `tarfile`/`tar` 即可读；写入器只产生 USTAR 头（不含 PAX/GNU 扩展、sparse、长名头）。

```
manifest.json           普通文件，必须是第一个条目
signatures/manifest.sig 普通文件，存在时必须是第二个条目
<其余条目>               普通文件与目录
```

`manifest.json` 即 `api/manifest/v1/manifest.schema.json` 描述的 manifest；`signatures/manifest.sig` 是对 manifest.json **原始字节**的 Ed25519 分离签名信封 `{"key_id":"ed25519:<64 hex>","signature":"<base64>"}`（直接复用 `sdk/manifest`，未重复实现）。`manifest.files` 列出除上述两条目外的**全部**文件，值形如 `sha256:<64 位小写十六进制>`。

- 归档**不接受**未知条目：既不在 `files` 中、也不是 `manifest.json`/签名/目录的条目一律拒绝（因此包内不可能夹带第四个东西）。
- 目录条目可选（`bin/` 是否存在都不影响读取）；写入器会为源目录中的每个目录写条目，但**不写** `signatures/` 目录条目（签名文件隐含其父目录）。

### 2.2 规范形式（打包器的确定性规则）

同一源目录 + 同一签名密钥 ⇒ **逐字节相同**的输出（测试 `TestPackDeterministic`，含"换一个目录打包结论相同"）：

- 条目按路径**字节序**排序（目录因此先于其子文件：`bin` < `bin/plugin`）；
- 路径相对、以 `/` 分隔、无空段/`.`/`..`、目录条目带结尾 `/`、文件条目不带；
- 每个头：`ModTime = 1970-01-01T00:00:00Z`（Unix 0，不用零值 `time.Time{}`，否则 Go 会退化为 PAX 头）、`Uid=Gid=0`、`Uname=Gname=""`、`Format=USTAR`；
- 模式：目录 `0755`、可执行文件 `0755`、其余文件 `0644`——**只保留可执行位**这一个权限信息；
- gzip 头：无 name/comment、`MTIME=0`、`OS=255`、`BestCompression`。

路径上限 255 字节（与 manifest `relpath` 的 `maxLength` 一致）。USTAR 单段名 100 字节的限制直接体现为 `PKG_ENTRY_HEADER`：单个路径段超过 100 字节或整体无法用 USTAR 编码时打包失败，而不是悄悄改用 PAX（保持"第三方实现只需 USTAR"）。源目录中的 `signatures/` 子树不参与打包，其中只允许 `signatures/manifest.sig`，其余文件报 `PKG_PATH_CONFLICT`。

### 2.3 manifest 的重写策略（为什么整体重编码而非原字节拼接）

`Pack` 需要把计算出的 `files` 写进 manifest，但签名必须覆盖**归档里的**那份字节。选择是：把源 manifest 严格解码成 JSON 树，替换 `files`，再以 `encoding/json` 的确定性输出（键按字典序、两空格缩进、`SetEscapeHTML(false)`、数字用 `json.Number` 原样回写）重新编码。

理由：

1. 只保留一个 JSON 解析器（就是下面那个会拒绝重复键的解码器），不需要为了定位 `files` 的位置再引入带偏移量的第二个解析器；
2. 除 `files` 外**所有值都原样保留**（`json.Number` 逐字回写，`"memory_max_mb": 32` 不会变成 `32.0`），`TestPackPreservesManifest` 钉住这一点；
3. 键序改变对 JSON 语义无影响，而且正是确定性的来源；
4. 重编码后立刻用 `manifest.Parse` 校验结果，因此"打包出来的包一定能在宿主侧通过严格解析"（含 `entrypoint`/schema/SBOM 等在 `files` 中、未知字段、`schema_version` minor 等全部安装器规则）。

源 manifest 若含重复键，`Pack` 直接失败（`PKG_MANIFEST_INVALID`）：静默保留最后一个键会让"作者写的 manifest"和"被签名的 manifest"不同，属于必须暴露的错误。

签名包还要求 `publisher.key_id` 等于签名密钥的 `KeyID`（`PKG_PUBLISHER_MISMATCH`）：宿主在验签后就会核对这一点，在打包时失败比在安装时失败便宜得多。

## 3. 读取与校验（安装器与第三方工具共用）

### 3.1 顺序（ARCH §6.2）

1. 压缩字节数（读取过程中上限，见 §3.3）；
2. gzip/tar 流解析；
3. **第一个条目必须是 `manifest.json`**，读入其原始字节（≤ 256 KiB）；
4. **第二个条目（若存在）必须是 `signatures/manifest.sig`**（≤ 1 KiB）；
5. `manifest.VerifyAndParse(rawManifest, rawSig, trust)`：大小 → 信封 → 信任根 → Ed25519 → 严格解析 → publisher 绑定。**在这之前不解释 manifest 的任何一个字段**；
6. 之后才读取其余条目：路径/类型/权限/重复/大小校验，边写边算 sha256；
7. 收尾：`manifest.files` 里每个文件都必须出现过；多出、缺少、摘要不符全部拒绝。

`ReadUnverified` 只跳过第 5 步的验签（仍做严格解析），供"即将重新签名"的工具使用（`qwqctl sign`）；安装路径禁止使用（`install.Extract` 调用 `Read`，`Read` 拿到 nil 信任根直接报错，杜绝"忘记传信任根"变成"跳过验签"）。

### 3.2 拒绝清单（结构化 code）

| code | 含义 |
|---|---|
| `PKG_TOO_LARGE` | 压缩后超过 `Limits.CompressedBytes` |
| `PKG_CORRUPT` | 不是 gzip、截断、tar 结构损坏 |
| `PKG_ENTRY_LIMIT` | 条目数超限 |
| `PKG_TOTAL_TOO_LARGE` / `PKG_FILE_TOO_LARGE` | 解压总量/单文件超限 |
| `PKG_COMPRESSION_RATIO` | 压缩比超限（decompression bomb） |
| `PKG_MISSING_MANIFEST` / `PKG_MISSING_SIGNATURE` / `PKG_ENTRY_ORDER` | 固定条目缺失或位置错误、重复 |
| `PKG_MANIFEST_TOO_LARGE` / `PKG_SIGNATURE_TOO_LARGE` | 固定条目过大 |
| `PKG_ENTRY_TYPE` | 符号链接、硬链接、字符/块设备、FIFO、sparse、扩展头 |
| `PKG_ENTRY_MODE` | setuid/setgid/sticky |
| `PKG_PATH_INVALID_UTF8` / `PKG_PATH_ABSOLUTE` / `PKG_PATH_TRAVERSAL` / `PKG_PATH_INVALID` / `PKG_PATH_TOO_LONG` / `PKG_PATH_TOO_DEEP` / `PKG_PATH_DUPLICATE` / `PKG_PATH_CONFLICT` | 路径类（`PKG_PATH_INVALID` 覆盖空段、`\`、控制字符） |
| `PKG_FILE_MISSING` / `PKG_FILE_UNLISTED` / `PKG_DIGEST_MISMATCH` | 文件集合与摘要 |
| `PKG_ENTRY_HEADER` / `PKG_SOURCE_INVALID` / `PKG_SOURCE_CHANGED` / `PKG_MANIFEST_INVALID` / `PKG_KEY_INVALID` / `PKG_PUBLISHER_MISMATCH` | 打包/签名侧 |

错误模型与 `sdk/manifest` 一致：容器问题返回 `*pkgfile.Error`（`Violations` 按 path/code/message 排序，上限 20 条，`Omitted` 计数，`Has(code)` 查询）；**签名与 manifest 校验失败直接返回 `*manifest.Error` 原对象**（code 与 JSON Pointer 与 manifest 包文档完全一致），用 `errors.As` 区分两类。I/O 错误按 Go 惯例原样返回（不包装成 code），便于 `errors.Is(err, fs.ErrNotExist)` 等判断。

路径规则细节：`..`/`.` 段、绝对路径、反斜杠、空段、C0/DEL 控制字符、非 UTF-8 一律拒绝；重复路径按 `strings.ToLower` 折叠比较（`manifest` 的 `files` 本就只允许 ASCII，所以折叠等价于 Unicode case folding；目录条目也参与比较）；`manifest.json`/`signatures/manifest.sig` 也登记进折叠表，防止 `Manifest.json` 之类的影子条目。

### 3.3 资源上限默认值与理由

`DefaultLimits()`（零值 `Limits` 即取默认；每个字段都可单独放大，但**不能**关闭——把值设大是显式行为）：

| 字段 | 默认 | 理由 |
|---|---|---|
| `CompressedBytes` | 256 MiB | 上限应覆盖"静态二进制 + UI 构建产物"的最大合理插件，同时限制下载落盘量 |
| `TotalBytes` | 768 MiB | 解压总量 ≤ 3× 压缩量；1C1G 节点上即使包被接受也不会写爆磁盘 |
| `FileBytes` | 256 MiB | 单文件超过压缩包上限本身没有意义 |
| `Entries` | 8192 | `files` 被 schema 限到 4096，目录再给一倍余量；防"百万空目录" |
| `CompressionRatio` | 200 | 正常插件（含文本 UI 资源）远低于此；一旦解压量/压缩量 > 200 基本只能是炸弹 |
| `RatioFloorBytes` | 8 MiB | 压缩比在最初几 KB 上没有意义（flate 会预读），先允许 8 MiB 产出再开始判比；8 MiB 小到不会造成实际磁盘压力 |
| `PathBytes` | 255 | 与 manifest `relpath` 的 `maxLength` 对齐 |
| `PathDepth` | 16 | 真实插件最深约 4 层（`ui/assets/x/y.js`），16 层足够宽松又能拒绝病态嵌套 |

压缩比不是"读完再判"：每读 32 KiB 就检查一次 `produced/consumed > CompressionRatio`（整除，避免乘法溢出），因此炸弹在写满 8 MiB 左右就被拒绝；`TestReadCompressionBomb` 与 `TestExtractRejectsCompressionBomb`（16 MiB 零字节文件，压缩后约 16 KiB）覆盖该路径，同时验证默认上限仍接受正常包。`TotalBytes` 也按解压产出（含 manifest 与签名）实时计。

## 4. 导出 API（`sdk/pkgfile`，Apache-2.0）

```go
const (
    Extension = ".ppkg"
    ManifestPath = "manifest.json"
    SignaturePath = manifest.SignaturePath          // "signatures/manifest.sig"
    MaxManifestBytes = manifest.MaxSize             // 256 KiB
    MaxSignatureBytes = manifest.MaxSignatureSize   // 1 KiB
    ModeDir  fs.FileMode = 0o755                    // 规范目录模式（归档内）
    ModeFile fs.FileMode = 0o644
    ModeExec fs.FileMode = 0o755
    MaxViolations = 20
    // 以及 CodeXxx 常量（见 §3.2）
)

type Limits struct { CompressedBytes, TotalBytes, FileBytes int64; Entries int;
                     CompressionRatio, RatioFloorBytes int64; PathBytes, PathDepth int }
func DefaultLimits() Limits

type FileInfo struct { Path string; Size int64; Digest string }
type Package struct { Manifest *manifest.Manifest; ManifestBytes []byte;
                      Signature *manifest.Signature; Files []FileInfo; Size int64; Entries int }

type Sink interface {
    CreateDir(path string) error
    CreateFile(path string, size int64, mode fs.FileMode) (io.WriteCloser, error)
}
type ReadOptions struct { Limits Limits; Sink Sink }

func Read(r io.Reader, ts manifest.TrustStore, opts ReadOptions) (*Package, error)
func ReadUnverified(r io.Reader, opts ReadOptions) (*Package, error)

type PackOptions struct { SigningKey ed25519.PrivateKey; Limits Limits }
func Pack(srcDir string, w io.Writer, opts PackOptions) (*Package, error)

func Sign(manifestBytes []byte, priv ed25519.PrivateKey) ([]byte, error)   // 返回信封字节
func Resign(r io.Reader, w io.Writer, priv ed25519.PrivateKey, limits Limits) (*Package, error)

const ( PrivateKeyPEMType = "PRIVATE KEY"; PublicKeyPEMType = "PUBLIC KEY" )
func MarshalPrivateKeyPEM(ed25519.PrivateKey) ([]byte, error)   // PKCS#8
func MarshalPublicKeyPEM(ed25519.PublicKey) ([]byte, error)     // PKIX
func ParsePrivateKeyPEM([]byte) (ed25519.PrivateKey, error)
func ParsePublicKeyPEM([]byte) (ed25519.PublicKey, error)

func DigestFile(dir, relPath string) (string, error)            // os.OpenInRoot 约束
func VerifyFile(dir, relPath, wantDigest string) error           // ExecStartPre 用
```

`Sink` 语义：`CreateFile` 返回的 `io.WriteCloser` 在**恰好** `size` 字节后收到一次 `Close`（失败时也会收到一次以放弃文件）；读取失败时 Sink 内可能残留部分内容，调用方必须整体丢弃（`install.Extract` 会删掉 staging 目录）。

## 5. 安装落盘（`internal/pluginhost/install`，AGPL-3.0-only）

```go
const ( StagingPrefix = ".staging-"; FileMode = 0o444; ExecMode = 0o555; DirMode = 0o555 )
var ( ErrTargetExists, ErrTargetMismatch, ErrStagedClosed error )

func VersionDir(pluginsRoot, id, version string) string        // <root>/<id>/<version>
func Extract(ctx context.Context, pkgPath string, trust manifest.TrustStore, stagingRoot string) (*Staged, error)
func CleanupStale(stagingRoot string, minAge time.Duration) ([]string, error)

type Staged struct { /* 私有 */ }
func (s *Staged) Manifest() *manifest.Manifest
func (s *Staged) Package() *pkgfile.Package
func (s *Staged) Dir() string          // Commit 前是 staging 目录，Commit 后是版本目录
func (s *Staged) Commit(finalDir string) error
func (s *Staged) Discard() error       // 幂等
```

- **落盘**：`Extract` 在 `stagingRoot` 下 `os.MkdirTemp` 建私有目录（0700），用 `os.OpenRoot` 打开，所有写操作经 `os.Root`（`MkdirAll`/`OpenFile`，`O_EXCL`）限制在其内；路径已由 `pkgfile` 校验，`os.Root` 是第二道防线。
- **权限**：文件创建即 `0444`（可执行 `0555`），`Close` 时再 `Chmod` 一次（压过 umask）再 `fsync` 再关闭；目录先 0700 可写，`finalize` 里统一改 0555 并逐目录 `fsync`（含 staging 根目录本身）。
- **原子发布**：`Commit` 先 `os.Lstat` 检查目标不存在（存在则 `ErrTargetExists`，版本目录不可变），`MkdirAll` 父目录，`os.Rename` 一步到 `<root>/<id>/<version>`，再 `fsync` 父目录。目标路径必须是 `VersionDir(...)`（绝对、clean、末两级为 `id`/`version`），否则 `ErrTargetMismatch`——这条检查在关闭根句柄**之前**做，所以目标不合法的 `Commit` 不会消耗 staged 包。
- **归属 root**：安装进程以 root 运行时 `verifyTreeOwner` 遍历已发布树断言 uid/gid 均为 0；非 root（测试）跳过并在注释/本文说明。`os.Root` 的句柄在重命名前关闭（部分平台不允许重命名已打开的目录）。
- **崩溃残留**：staging 目录名带 `.staging-` 前缀；`CleanupStale(root, minAge)` 只删除该前缀且比 `minAge` 更老的条目（`minAge=0` 表示全部），先递归 `chmod` 可写再 `RemoveAll`（发布态是只读树，直接删会失败）。建议 Agent 启动时调用 `CleanupStale(stagingRoot, time.Hour)`。
- **并发边界**：`Commit` 的"检查不存在 + rename"不是原子的，同一版本的并发安装必须由调用方串行化（ARCH §6.3 的"单插件更新锁"）；`CleanupStale` 的 `minAge` 也是为并发安装留的余量。`Discard` 幂等；`Commit`/`Discard` 之后再次调用返回 `ErrStagedClosed`（`Discard` 在 `Commit` 之后是 no-op）。
- **同文件系统**：stagingRoot 必须与 pluginsRoot 同文件系统（rename 不跨设备）。建议 `pluginsRoot=/var/lib/qwq/plugins`、`stagingRoot=/var/lib/qwq/plugins/.staging`（后者随 pluginsRoot 一起归 root、同盘）。

`Extract` 只证明"包是可信且完整的"。target/ABI/依赖/能力差异仍由调用方在 staged 期间用 `Staged.Manifest()` 检查，通过再 `Commit`，不通过 `Discard`——这样被拒绝的安装永远不会出现在 plugins root 下。

## 6. `cmd/qwqctl`

| 命令 | 说明 |
|---|---|
| `keygen -out <prefix>` | 生成 Ed25519 密钥对：`<prefix>.key`（PKCS#8 PEM，0600，`O_EXCL` 不覆盖）、`<prefix>.pub`（PKIX PEM，0644），打印 `key_id: ed25519:<hex>` |
| `pack -src <dir> -out <file.ppkg> [-key <priv.pem>]` | 打包（带 `-key` 即签名）；源目录必须含 `manifest.json` |
| `sign -key <priv.pem> [-out <file.ppkg>] <file.ppkg>` | **就地重写**（无 `-out` 时）：写临时文件 + rename，失败不动原文件；仅替换签名条目，其余条目逐字节复制 |
| `verify -trust <pub.pem> [-trust ...] [-files] <file.ppkg>` | 验签 + 严格解析 + 全量摘要，打印 manifest 摘要与 `result: OK`；失败非零退出 |

退出码：`0` 成功、`1` 校验/I-O 失败、`2` 用法错误。全部用标准库 `flag`，入口仍是 `run(args []string, stdout, stderr io.Writer) int`，`version`/`help` 行为与测试保持不变。`-trust` 可重复或逗号分隔。

`pack`/`sign` 通过同目录临时文件 + `fsync` + `rename` 写出，任何失败都不会留下半个包（`TestPackRejectsBadManifest` 断言失败后目标文件不存在）。

注意：私钥文件名以 `.key` 结尾，命中仓库 `.gitignore`；`keygen` 也不会覆盖已存在的密钥。密钥应生成在仓库之外。

## 7. 验证命令与结果

均在 Linux 构建机（`scripts/remote.sh`，`QWQ_REMOTE_SRC=p2b`，Go 1.27.3，3 核共享机）上执行：

| 命令 | 结果 |
|---|---|
| `gofmt -l sdk/pkgfile internal/pluginhost/install cmd/qwqctl` | 空输出（已 gofmt） |
| `go vet ./sdk/pkgfile` / `go vet ./internal/pluginhost/install` / `go vet ./cmd/qwqctl` | 通过 |
| `staticcheck ./sdk/pkgfile ./internal/pluginhost/install ./cmd/qwqctl` | 通过（0 条） |
| `go test ./sdk/pkgfile ./internal/pluginhost/install ./cmd/qwqctl` | 全部 ok（约 0.7 s） |
| `CGO_ENABLED=1 go test -race -count=1` 同上三个包 | 全部 ok（4.0 s / 1.5 s / 1.4 s） |
| `cd sdk && GOWORK=off go test ./... && go vet ./...` | 全部 ok（含 `sdk/abi`、`sdk/manifest`、`sdk/pluginsdk`） |
| `cd sdk && GOWORK=off go test -run=^$ -fuzz=^FuzzRead$ -fuzztime=30s ./pkgfile` | PASS，44115 次执行，0 失败、0 panic（共享构建机 CPU 被其他会话占用后 exec 速率降为 0/s，属资源竞争，非卡死） |
| SDK 边界 `go list -deps`（`scripts/check.sh` 形式） | 只出现 `github.com/qwq-panel/qwq/sdk/...`，无宿主包 |
| `GOWORK=off GOOS=linux GOARCH=amd64/arm64 go build ./cmd/... ./internal/pluginhost/install` | 通过 |
| `GOWORK=off GOOS=windows GOARCH=amd64 go build`（两个包，本人改动） | 通过（非 unix 走 `owner_other.go`） |
| `python3 tools/repo_lint.py` | `ok spdx / ok boundary / ok secrets / ok versions` |

测试清单（对应任务要求）：

- `sdk/pkgfile`：`TestPackDeterministic`（两次与跨目录逐字节相同）、`TestPackLayout`（条目顺序/头字段/模式/摘要/无 `signatures/` 目录）、`TestPackPreservesManifest`、`TestPackUnsigned`、`TestPackRejects`（符号链接、过深/过长路径、`signatures/` 杂项、保留名大小写变体、缺失被引用文件、重复键、非对象、非法 JSON）、`TestPackPublisherMismatch`、`TestPackNoManifest`、`TestPackNotADirectory`；`TestReadRoundTrip`、`TestReadUnsigned`、`TestReadRequiresTrustStore`、`TestReadRejects`（篡改摘要、多余文件、缺文件、符号链接/硬链接/字符设备/FIFO、`..`、绝对路径、空段、反斜杠、控制字符、非法 UTF-8、大小写重复、文件/目录冲突、setuid、manifest 非首条、签名非第二条、重复 manifest）、`TestReadCorrupt`、`TestReadSignatureErrors`（不受信密钥、publisher 绑定、篡改 manifest、坏信封）、`TestReadLimits`（6 项上限）、`TestReadCompressionBomb`、`TestReadSinkFailure`；`TestSignEnvelope`、`TestSignRejects`、`TestPEMRoundTrip`、`TestDigestAndVerifyFile`、`TestResign`（重签逐字节稳定、幂等）、`TestResignUnsigned`、`TestResignRejectsBrokenInput`；`FuzzRead`。
- `internal/pluginhost/install`：`TestExtractCommit`（全流程 + 发布后 `VerifyFile` 复算摘要 + 权限 + 二次安装 `ErrTargetExists`）、`TestExtractRejectsBadPackages`（8 个子用例）、`TestExtractRejectsUntrustedKey`、`TestExtractRequiresTrustStore`、`TestExtractRejectsCompressionBomb`、`TestDiscard`（幂等 + 之后 `Commit` 报 `ErrStagedClosed`）、`TestCommitTargetChecks`、`TestCleanupStale`、`TestCleanupStaleRemovesReadOnlyTrees`（模拟崩溃残留）。

## 8. 与其他任务的接口

1. **P2-T5（`ExecStartPre` 摘要校验）**：直接复用 `pkgfile.VerifyFile`。单元模板渲染时可用 Agent 在安装阶段已验签的 manifest 摘要：

   ```go
   // 启动前：断言入口文件仍与 manifest 一致
   err := pkgfile.VerifyFile(versionDir, m.Entrypoint, m.Files[m.Entrypoint])
   ```

   若希望 `ExecStartPre` 完全自包含（不依赖宿主进程），用一个小 helper 读版本目录里的 manifest：

   ```go
   raw, err := os.ReadFile(filepath.Join(versionDir, "manifest.json"))
   m, err := manifest.Parse(raw)                 // 已安装树由 root 只读，此处做完整性检查
   err = pkgfile.VerifyFile(versionDir, m.Entrypoint, m.Files[m.Entrypoint])
   ```

   两种情况都只需要 `sdk/pkgfile` + `sdk/manifest`；`DigestFile` 可以用来打印实际摘要以便诊断。若 P2-T5 需要"由 qwqctl 子命令执行"，建议新增 `qwqctl plugin-verify-entrypoint <versionDir>`（本人范围外，未添加）。

2. **P2-T7 / P3（Supervisor、安装编排）**：调用顺序 `Extract` → 检查 ABI/target/依赖/能力差异 → `Commit(install.VersionDir(pluginsRoot, id, version))`/`Discard`。同一插件的安装必须持 ARCH §6.3 的单插件锁（`Commit` 的存在性检查与 rename 非原子）；Agent 启动时调用 `CleanupStale(stagingRoot, time.Hour)`。stagingRoot 与 pluginsRoot 必须同文件系统。

3. **P2-T6 / 安装向导**：`Staged.Package()` 已含 manifest、签名 key_id、文件与摘要列表，可直接用于"安装确认页"（能力、资源预算、文件清单）；`Staged.Manifest()` 用于策略检查。失败时错误可能是 `*pkgfile.Error`（容器/摘要）或 `*manifest.Error`（签名/manifest），两类 code 都可直接映射成面向用户的说明；`install` 自身的拒绝用 `errors.Is` 对 `ErrTargetExists`/`ErrTargetMismatch`/`ErrStagedClosed` 判断。

4. **P1-T8 / 目录与 OpenAPI**：`verify` 的输出结构（id/version/target/entrypoint/publisher/签名 key/文件数/字节数/manifest sha256）就是展示包信息需要的最小集合，可直接照搬；`pkgfile.Package` 是纯数据，不依赖宿主包。

5. **P2-T8 / 安装策略（doctor 门禁）**：`Limits` 已是可注入的，策略层可以按节点配额收紧并传给 `Read`；注意 `install.Extract` 当前签名固定使用 `DefaultLimits()`（任务要求），如需按策略收紧，建议后续给 `Extract` 增加 `ExtractWithOptions`（未实现，避免超出本任务约定的 API）。

6. **索引/TUF（§10.4）**：本任务只做单包校验，未接 `go-tuf`、SBOM 策略与防回滚；下载层应在落盘前用 `Limits.CompressedBytes` 预检（`Content-Length` 与实测都查）。

## 9. 已知限制与后续

- **密钥轮换**：`Resign` 逐字节保留 manifest，因此只能用 `publisher.key_id` 指定的那把钥匙重签（与 `Pack` 一致）；轮换需要改 manifest 再签，即重新 `Pack`（或未来加"替换 manifest 字节"的 API）。这是有意为之：签名不应顺带改身份。
- **manifest 版本超前**：`Pack` 用**本宿主**的 `manifest.Parse` 校验，因此比宿主更新 minor 的插件无法在旧宿主上打包（没有 `SkipManifestCheck` 逃逸口）。
- **target/ABI 不匹配**：不在本包检查（需要节点信息），由调用方在 staged 期间判断。
- **SBOM 内容**：只校验 `attestations/*` 出现在 `files` 中且摘要一致，不解析 SPDX/in-toto 内容（属 P2-T8 策略）。
- **USTAR 限制**：单段名 > 100 字节或整体无法用 USTAR 编码时拒绝（`PKG_ENTRY_HEADER`）；如需支持超长路径，需同时放宽 `Limits.PathBytes` 与 `manifest` 的 `relpath`，属格式变更。
- **目录 fsync**：Windows 不支持，`syncPath` 在该平台忽略错误；生产目标为 Linux。
- **非原子存在性检查**：见 §5 并发边界，依赖调用方的单插件锁。
- **未做**：包内 manifest 与 `GetDescriptor` 的一致性校验（加载期，P2-T7）、签名密钥加密存储（PKCS#8 明文，仅靠 0600 权限）、多签名/阈值签名。
