# ADR-0006：公共 API 的类型生成方式

- 状态：Proposed（P0-T5 交付，评审通过后改为 Accepted）
- 日期：2026-11-01
- 范围：从 `api/public/v1/openapi.yaml` 到 Shell（TypeScript）、宿主网关（Go）、`clientcore`（Go）与动作目录的生成链路；以及与之相关的两条契约约定：revision 不用 ETag，agent 工具一律 POST + JSON
- 关联：ARCH §4.1、§11；ADR-0004 D2、D5、D7、D8；ADR-0005 Q2；审查 F3、F4

## 背景

ARCH §4.1 规定 OpenAPI 3.1 是公共 DTO 的唯一来源，Shell 的 TypeScript 客户端与 `clientcore` 的 Go 客户端都从它生成。P0-T5 交付了骨架 `api/public/v1/openapi.yaml`（33 条路径、43 个 operation），由 vacuum 与项目规则集 `tools/vacuum/ruleset.mjs` 检查。还需要决定：

1. Shell 的 TS 类型怎么生成；
2. 宿主 Go 侧 DTO 怎么保证与 OpenAPI 一致；
3. `clientcore` 的 Go 客户端怎么来；
4. 动作目录怎么读取宿主路由上的 `x-qwq-action`；
5. 乐观并发用 JSON 中的 `expected_revision`，还是 HTTP 的 `ETag`/`If-Match`。

候选生成器的情况。Go 生成器于 2026-11-01 在构建机上用本仓库的 openapi.yaml 实际跑过（临时目录，未进入仓库）；TS 工具只查了 npm 元数据与官方文档，因为本任务不允许安装 Node 包。

| 工具 | 版本 | 许可证 | OpenAPI 3.1 | 对本 spec 的结果 |
|---|---|---|---|---|
| oapi-codegen | v2.8.2（2026-10-31） | Apache-2.0 | README 声明支持 3.0 与 3.1（#2336：`type: [T, "null"]`、`oneOf` + `const` 枚举、webhooks）；解析器 kin-openapi v0.142.0 | `models` + `client` 生成成功，`go vet` 通过，19034 行；只生成 `models` 为 3839 行。`allOf` 展平为结构体；`anyOf` 生成 `json.RawMessage` 包装加 `AsX()`/`FromX()`；枚举是 `type X string` 加常量，解码时不校验；`oneOf: [Revision, null]` 变成 `*Revision`，null 与缺省无法区分；没有 `type` 的字段是 `interface{}`。union 的合并函数引入 `github.com/oapi-codegen/runtime` v1.8.0（Apache-2.0；间接依赖 go-jsonmerge（MIT）与 google/uuid（BSD-3-Clause）） |
| ogen | v1.24.0（2026-08-07） | Apache-2.0 | 解析 3.1，把 `type: [T, 'null']` 折叠为 nullable | 默认失败："complex anyOf is not implemented"（`StreamFrame.data`）。设置 `ignore_not_implemented: [all]` 后跳过 `GET /api/v1/events`，客户端加服务端共 94263 行。生成的客户端解码响应后调用 `Validate()`，枚举值不在列表中即报错 |
| openapi-typescript | 7.13.0 | MIT | 文档声明支持 3.0 与 3.1；只生成类型（`.d.ts`），没有运行时 | 未实测。直接依赖 6 个包（含 `@redocly/openapi-core`），peer 依赖 TypeScript 5 |
| openapi-fetch | 0.17.0 | MIT | 与 openapi-typescript 配套的 fetch 封装，依赖 1 个包 | 未实测 |

## 决策

### D1 TypeScript：openapi-typescript 只生成类型

- P5 建立 `web/shell/` 时引入 openapi-typescript（devDependency，版本锁在 `package-lock.json`，装在项目内 `node_modules/`），生成 `web/shell/src/api/schema.d.ts`。产物提交入库，CI 重新生成并比较差异，所以只改 Go 的贡献者不需要 Node。
- 运行时只有一层手写的薄封装：加 `X-CSRF-Token`；为变更请求生成 `Idempotency-Key`，重试时复用同一个；解析 `application/problem+json`；区分 200 与 202；SSE 订阅与重连。用生成的 `paths` 类型给它做泛型约束。不引入 openapi-fetch，因为它不处理这些横切逻辑，薄封装要写的代码不会因此减少。
- 可扩展枚举（`x-qwq-extensible-enum: true`，如 `ProblemCode`、`Role`）在封装层声明为"已知值 | `(string & {})`"，遇到未知错误码按 HTTP 状态类处理（openapi.yaml 中的约定）。
- 前端只做类型与必填检查，`pattern` 交给后端（审查 F3），不需要运行时 schema 校验库。
### D2 宿主 Go DTO：oapi-codegen 只生成模型，路由与处理器手写，用契约测试保证一致

- 用 oapi-codegen 的 `generate: {models: true}` 生成到 SDK 模块的 `sdk/gen/publicapi/`。它是公共契约，与 proto 生成代码一样放在 Apache-2.0 分区（ADR-0005 Q2），宿主、`clientcore` 与第三方客户端都可以导入。生成器放在独立的工具模块 `tools/oapi/`（与 `tools/buf` 一样用 `tool` 指令锁版本），P1-T1 引入；本任务不改根模块。
- 网关用这些类型解码请求、编码响应。**不生成服务端路由**（strict server、chi/net/http 适配都不用）。原因：网关中间件的顺序是信任边界，必须由手写代码控制（大小与深度限制 → 认证/CSRF → 幂等键 → schema 校验 → 有效风险 → 创建 operation）；插件 operation 路由的请求 schema 来自 manifest，生成器表达不了。
- 一致性靠三层检查：
  1. 编译期：处理器只使用生成的类型；
  2. P0-T6 契约测试：宿主注册的路由集合（方法 + 路径）必须与 openapi.yaml 的 paths 完全相同；`components/schemas` 用 SDK 已有的 JSON Schema 2020-12 校验库（`santhosh-tekuri/jsonschema/v6`）编译（3.1 的 schema 就是 2020-12），用来校验测试 fixture；
  3. P1 集成测试：测试构建中，网关用对应 operation 的响应 schema 校验每个响应，不匹配即失败。
- 生成代码会依赖 `github.com/oapi-codegen/runtime`，只因 `StreamFrame.data` 这个 `anyOf` 的合并函数。这个依赖可以接受（Apache-2.0）。如果 P1-T1 想去掉它，可以把 `StreamFrame.data` 改为带 `discriminator` 的 `oneOf`，届时再实测。

### D3 clientcore：复用生成的模型，传输层手写

- `clientcore` 导入 `sdk/gen/publicapi` 的模型，手写传输层：会话/令牌、`Idempotency-Key` 的生成与重试复用、problem+json 解码、202 之后跟随 `Location` 或事件、SSE（`Last-Event-ID` 续传，收到 `resync` 后重拉快照）、退避。生成的客户端不做这些。
- 不使用 oapi-codegen 的 `client: true`。gomobile 导出层按 ARCH §11 只暴露粗粒度的 `Execute(requestJSON)`，逐 operation 生成的方法既导不出去，又增大二进制。
- 解码响应时不按枚举白名单校验。宿主新增错误码或状态时，旧客户端照常工作。这也是不选 ogen 的原因之一。

### D4 动作目录：构建时从 `x-qwq-action` 生成静态表

- P1-T8 写一个小生成器（`go generate`，在宿主模块中）：读 openapi.yaml，取出所有带 `x-qwq-action` 的 operation，生成 `describe_action` 需要的 `args_schema`（路径参数 + 请求体成员 + DELETE 的 `expected_revision` 查询参数，展平为一个对象；重名在生成时报错）与结果 schema，输出一个 Go 源文件，提交入库，CI 比较差异。宿主运行时不解析 YAML、不嵌入 openapi.yaml，空闲内存与启动时间都不增加。
- 插件那一半来自 manifest 的 `operations`，在安装时读入，与宿主的静态表合并成一个目录。
- `x-qwq-action` 与 manifest operation 同构（字段、枚举、`destructive ⇒ risk=high`、`read ⇒ idempotent`、`undo` 指向已有的宿主动作），由 vacuum 规则 `qwq-action-shape` 检查。`x-qwq-action-from: manifest` 标记插件调用路由；`x-qwq-action-exempt` 标记有意不进目录的变更路由（会话、批准、委托管理等）。每个变更路由必须三者选一（`qwq-action-registered`）。
### D5 revision 只用 `expected_revision`，不用 ETag/If-Match

修改资源的请求在 JSON 请求体中带 `expected_revision`（DELETE 没有请求体，放在查询参数），不匹配返回 `409 REVISION_CONFLICT` 并附 `current_revision`；资源与列表响应带 `revision` 字段。v1 不提供 `ETag`/`If-Match`，也不同时支持两者：

- AI 工具调用只有一个 JSON 参数对象，模型设置不了 HTTP 头。版本号放在参数里，人、Shell、AI 用同一种写法，`read` 返回的 `revision` 原样填进 `execute` 即可。
- 一个 plan 的 preconditions 可能涉及多个 subject（ADR-0004 D7），HTTP 条件头只能表达"当前这个表示"。body 字段与 `Precondition{subject, revision}` 同构，插件侧直接映射到 proto。
- `fields` 投影使同一资源有多个"表示"，强 ETag 要按表示计算，而并发控制关心的是资源的版本，不是表示的版本。
- 两套机制并存要定义 412 与 409 的优先级、两者都传时谁说了算，徒增测试面。
- 不做 HTTP 缓存：`/api/v1` 一律 `Cache-Control: no-store`，增量读取用 `since_revision`（未变化时返回 `unchanged=true` 或 `delta=true` 的空增量），所以不需要条件 GET。

revision 对客户端是不透明字符串，只比较相等。服务端实现可以是单调整数（ADR-0004 D2），但客户端不能解析或比较大小，以后改成复合版本（如节点 + 序号）不算破坏性变更。

### D6 agent 工具一律 POST + JSON

`/api/v1/agent/*` 的七个工具全部是 `POST`，参数只放在 JSON 请求体中，不用查询参数、路径参数或业务头：

- MCP 的 `inputSchema` 与 function calling 的 `parameters` 都是一个 JSON Schema 对象。适配器把请求体 schema 原样作为工具 schema，把工具结果原样作为响应，没有"哪个参数放在哪里"的拼装规则；HTTP 路径的最后一段就是工具名（`find_actions` 等），由 `qwq-path-segments` 检查。
- 参数 schema 是平坦的 `type: object`，顶层不用 `oneOf/anyOf/allOf`，因为部分 function-calling 实现只接受顶层 object。"`plan_id` 或 `action`+`args`" 这类约束由宿主校验（`ExecuteRequest` 的说明），由 `qwq-agent-mcp` 检查。
- 工具结果的语义放在 body 里：`execute`/`wait`/`cancel` 恒为 200，看 `OperationOutcome.status`，模型不需要理解 200 与 202 的区别。错误码只用于真正的调用失败。
- 只读工具（`find_actions`、`describe_action`、`read`、`plan`、`wait`）不需要 `Idempotency-Key`；`execute`、`cancel` 需要，由适配器从工具调用 ID 派生，保证传输层重试安全。MCP 注解写在 `x-qwq-mcp.annotations` 中。

### D7 让生成器顺利工作的写法约定（由 vacuum 规则检查的部分已注明）

- JSON 成员一律 snake_case，与 proto JSON 名和 manifest 一致（`qwq-snake-case-properties`）。
- 请求体 `additionalProperties: false`（`qwq-request-closed`），拼错的参数会被拒绝；响应保持开放，向后兼容地加字段不破坏旧客户端。`args`、`payload` 这类按目标动作自身 schema 校验的成员除外。
- 会增长的枚举标 `x-qwq-extensible-enum: true`；闭集枚举（`OperationStatus`、`ActorKind`）由 `qwq-fixed-enums` 锁定。
- 可空字段尽量用"缺省"表达，少用 `oneOf: [X, null]`，因为 oapi-codegen 把两者都映射为指针，无法区分。确需区分时在 description 中写明。
- 少用 union。必须用时优先带 `discriminator` 的 `oneOf`；整数写 `format: int32/int64`；可能超过 2^53 的整数（事件 `sequence`）用十进制字符串，避免 JavaScript 丢精度。
## 落地顺序

| 任务 | 内容 |
|---|---|
| P0-T6 | `scripts/check.sh` 调用 vacuum（命令见 `tools/vacuum/ruleset.mjs` 文件头）；契约测试骨架：schema 编译、fixture 校验 |
| P1-T1 | `tools/oapi/` 工具模块；生成 `sdk/gen/publicapi/`；CI 比较生成差异 |
| P1-T7 | 网关使用生成的模型；路由集合与 openapi.yaml 一致的测试；测试构建中的响应校验 |
| P1-T8 | 动作目录生成器与静态表 |
| P5 | `web/shell/` 引入 openapi-typescript 与薄封装；实测它对本 spec 的输出 |
| P8 | `clientcore` 传输层 |

## 代价

- 生成代码（Go 模型、TS 类型、动作目录表）要提交入库，openapi.yaml 每次修改都要重新生成；CI 用差异检查兜底。
- 处理器与路由手写，路由与 spec 的一致性完全依赖契约测试，所以那条测试是必需的，不是可选的。
- oapi-codegen 的 3.1 支持是近期才加的；`$dynamicRef`、`unevaluatedProperties`、`prefixItems` 等 3.1 特性的支持情况未知。spec 中避免使用它们；升级生成器时比较生成差异。
- `StreamFrame.data` 的 union 带来一个运行时依赖（及其间接依赖）。
- TS 侧未实测。P5 引入时如果发现 openapi-typescript 对某些写法的输出不可用，按 D7 调整 spec，不换成运行时代码生成器。

## 未采用

- **ogen**：对本 spec 默认生成失败（complex anyOf）；按枚举严格校验响应，宿主新增错误码会让旧的移动端客户端解码失败，违背可扩展错误码的约定；默认同时生成客户端与服务端（94263 行，oapi-codegen 的模型 + 客户端为 19034 行），对 gomobile 二进制不利。它的免反射编解码与严格校验，对本项目的请求量没有意义。
- **oapi-codegen 的 strict server 或路由适配器**：网关中间件链是信任边界，插件路由的 schema 来自 manifest，见 D2。
- **手写 Go DTO**：三端手写会逐渐不一致，这正是审查 F4 要避免的；生成模型的成本很低。
- **由 Go 代码生成 OpenAPI（code-first）**：违背 ARCH §4.1"OpenAPI 是唯一来源"，而且 Shell 与第三方需要在宿主实现之前就拿到契约。
- **ETag/If-Match（单用或与 body 字段并用）**：见 D5。
- **运行时嵌入并解析 openapi.yaml 来构建动作目录**：增加常驻内存与启动时间，而目录内容在构建时就已确定。
- **openapi-fetch 或生成的 TS 客户端**：横切逻辑仍然要手写，见 D1。

## 四个问题（HANDOFF §1.3）

1. 空闲开销：0。生成发生在构建时，动作目录是静态表。
2. 峰值：不涉及。
3. 失败：生成器或 spec 出错只会让 CI 失败，不影响运行中的宿主。
4. ABI：不改插件 ABI 与 proto；确定了公共 API 的类型来源。
