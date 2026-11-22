# ADR-0008：宿主内部结构（P1）

- 状态：Accepted（随 P1 施工补充）
- 日期：2026-11-01
- 关联：ARCH §4、§7、§8；ADR-0004；ADR-0007；`IMPLEMENTATION-PLAN.md` P1

## 背景

P1 要做出最小宿主（standalone）。几条横切的内部约定如果每个任务各自决定，P1 的各个包会互不兼容：包的分工、写事务边界、revision 的取值、事件日志与 outbox 的关系、ID 与时间格式、配置文件、secret 的存放。本 ADR 一次定下来；公共 API 的形态以 `api/public/v1/openapi.yaml` 为准。

## 决策

### 1. 包与依赖方向

```text
internal/platform/{config,logging,clock,ids,problem}   无宿主内部依赖
internal/storage            SQLite 连接、迁移、写事务、事件日志、备份
internal/identity           用户、角色、口令、会话、TOTP、恢复码、初始化 token、登录退避
internal/authz              Actor、RBAC、委托令牌、服务账号；有效权限计算
internal/operations         operation 状态机、幂等键、attempt、审计、事件；plan、approval、有效风险
internal/secrets            secret 引用与加密存储
internal/events             事件日志尾随、SSE 分发、Last-Event-ID 续传
internal/catalog            动作目录（宿主 OpenAPI 的 x-qwq-action + 插件 manifest）与本地检索
internal/gateway            HTTP 服务、中间件、路由、problem+json、SSE 端点
internal/agentapi           /api/v1/agent/* 七个工具
internal/tlsmgr             ACME、自签名、证书热加载
internal/controller         组装以上部件；Dispatcher 接口（P1 为假实现，P2 换成插件运行时）
```

上层依赖下层，同层不互相导入；`gateway` 只调用领域包的导出函数，不写 SQL。每个领域包拥有自己的表与查询，表结构变更集中在 `internal/storage/migrations/` 的有序 SQL 文件中（一个顺序，便于审阅与回滚判断）。

### 2. 唯一写入通路与事务边界（ADR-0004 D1）

- 宿主资源的每次修改都经 `operations.Run`：在**一个**写事务里写领域行、operation 行、审计行与事件行；事务提交后唤醒事件分发。任何一步失败整个事务回滚，不会出现"数据改了但没有事件"或相反。
- 例外只有认证流程（登录、登出、TOTP 校验、会话续期）：它们改变的是会话状态而不是资源，只写审计，不创建 operation。
- 长任务（`mode=job`）先在一个事务中创建 operation（`PENDING`/`AWAITING_APPROVAL`），之后每次状态推进一个短事务；不持有长事务。

### 3. SQLite 纪律（ARCH §8.1）

- 一个写连接（`MaxOpenConns=1`，DSN `_txlock=immediate`，所有写事务以 `BEGIN IMMEDIATE` 开始）+ 一个只读连接池（`mode=ro`、`query_only`，默认 4 个连接）。
- PRAGMA：`journal_mode=WAL`、`synchronous=FULL`、`foreign_keys=ON`、`busy_timeout=5000`、`journal_size_limit`；只读连接 `cache_size` 较小。空闲时 `wal_checkpoint(TRUNCATE)`。
- 写事务内不做网络调用、不调用插件；需要插件参与的操作先提交状态，再在事务外调用，结果再用新事务写回。
- 备份用 `VACUUM INTO`；启动时 `quick_check`。

### 4. revision 与事件日志

- 事件日志 `event_journal` 的 `seq` 是全库单调递增的整数，就是 SSE 的 `id` 与 `Last-Event-ID`。
- **资源的 revision 等于最后一次修改它的那条 `resource.changed` 事件的 `seq`**，在同一事务中写入。因此 revision 全库唯一且递增：删除后重建的资源不会与旧资源的 revision 撞号；`since_revision` 与事件流用同一个坐标。公共 API 中 revision 是十进制字符串，客户端按不透明值处理，只比较相等。
- 写连接只有一个，`seq` 的分配顺序就是提交顺序，尾随日志的读者不会看到空洞。
- standalone 中 `event_journal` 同时充当 transactional outbox。日志按"保留最近 N 条或 T 天，取较大者"清理；`Last-Event-ID` 早于最旧保留条目时，SSE 发 `resync`，客户端重新拉快照。
- 插件自有资源的 revision 由插件给出（不透明字符串，ADR-0007）。

### 5. ID 与时间

- ID 为 TypeID 格式：`<前缀>_<UUIDv7 的 26 位小写 Crockford base32>`（`internal/platform/ids`），如 `op_01jc…`。按时间排序，便于主键追加写和游标分页；前缀让人与 AI 一眼看出对象类型。ID 不携带权限。
- trace_id 采用 W3C Trace Context 格式（32 位十六进制），便于以后接 OpenTelemetry。
- 时间在 API 与数据库中都用 RFC 3339 UTC（毫秒），由 `clock.Clock` 提供；业务代码不直接调用 `time.Now`。

### 6. 引导配置

`/etc/qwq/qwq.json`（`internal/platform/config`）只放打开数据库之前需要的内容：角色、目录、监听地址、TLS 模式、日志。严格解码（未知字段、多余数据、非法值都报错）。默认只监听 `127.0.0.1:8443`，首次初始化经 SSH 隧道或一次性链接（ARCH §4.1.1）。其余设置存数据库，经 operation 修改。选 JSON 而不是 TOML/YAML：不增加依赖，文件内容很少，且大多由安装器写入。

### 7. secret 存储

- secret 值用 AES-256-GCM 加密后存数据库，附带 key id；主密钥在 `data_dir/keys/master.key`（0600，归宿主用户），不进数据库，与数据库分开备份（ARCH §8.3）。
- 业务表、配置快照、事件、审计中只出现 secret 引用（`sec_…`）。日志由 `logging` 的脱敏规则与 `logging.Secret` 类型兜底。
- 主密钥轮换：新密钥加密新值，旧值在后台重新加密；细节在 P1-T6 实现时补充。

### 8. 插件调用的接缝

P1 没有插件运行时。`controller.Dispatcher` 接口代表"把一次 operation 交给某个插件实例"，P1 用测试中的假实现（行为与 ADR-0007 的场景测试一致），P2 换成真实的 Supervisor。动作目录在 P1 读取 fixture manifest。

## 代价

- revision 取事件序号，要求每次修改资源都写事件——这本来就是 ADR-0004 的纪律，这里只是把它变成数据上的必然。
- 单一迁移目录意味着领域包不能各自演进表结构；换来的是一个确定的迁移顺序。

## 未采用

- 每行独立计数的 revision：删除重建后会撞号，客户端持有的旧 revision 可能误匹配新资源。
- 独立的 outbox 表 + 投递进程：standalone 中事件日志本身就是 outbox；多节点时再为节点通道加投递状态。
- ORM 或查询生成器：表少、查询简单，手写 SQL 加测试更透明。
