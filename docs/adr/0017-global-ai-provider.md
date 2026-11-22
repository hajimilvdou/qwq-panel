# ADR-0017：全局 AI 提供方与 Key 归属

- 状态：Accepted（2026-11-11，阶段 2 后端缺口 2）
- 日期：2026-11-11
- 关联：ADR-0004 D6、ADR-0010 §5（原生 agent 会话）、ADR-0016、ARCH §4.1.1；AGT-02（`secrets.RevealOwned`）、AGT-03（出站控制）

## 背景

AGT-02 之后每个会话自带一个 API Key（`PUT /agent-sessions/{id}/api-key`，owner 是会话自身），适合"每个用户自带 Key"。家庭/小团队的实际用法是管理员配置一套全局 AI 服务（地址 + 模型 + Key），所有会话共用；密钥必须有属主、只写、可解密校验，且 Key 永远不能被发到未经管理员认可的其他地址上。本 ADR 定义这项资源与其会话解析规则（GAPS 缺口 2）。

## 决策

1. **资源**：`ai_providers`（迁移 `0012_ai_providers.sql`）：`provider_id`（`aip_`）、`name`（唯一）、`kind`（`openai_compatible`）、`base_url`、`model`、`api_key_ref`、`is_default`（部分唯一索引，最多一个）、时间与 `revision`。`GET /api/v1/ai/providers` 任何登录主体可读；非管理员拿到精简投影（`provider_id`、`name`、`model`、`is_default`、`has_api_key`），`base_url` 不出现——模型流量的去向是管理员信息。create/update/delete 走普通 operation（`host.ai_providers.*`，admin 专属、human-only），列表外不新增读取路由。
2. **Key 归属**：secret 的 owner 是 `ai_providers/<id>`，purpose 是 `agent.native.api_key`；只经 `secrets.RevealOwned` 以该 owner + purpose 解密，别的引用一律打不开。`PUT/DELETE /api/v1/ai/providers/{id}/api-key` 是机密例外路由：不进 operations（明文不得落进 `operations.args` 与幂等重放），写审计（无明文），发 `resource.changed`（`/has_api_key`），DTO 只暴露 `has_api_key`。删除提供方在**同一事务**里 `DeleteOwner` 清掉 Key。
3. **Key 绑定地址**：改 `base_url` 会清掉已存 Key（比 GAPS 下限更严）。否则一个被盗的管理员会话可以把地址改到自己的服务器，再用"测试连接"把 Key 送出去；换地址后重新填 Key 是一步明确的动作。
4. **删除守卫**：默认提供方在其他提供方仍存在时拒绝删除（`409 STATE_CONFLICT`），避免误删后没有默认提供方；请求时先拒（含未知 id 的 404），执行事务里再查一次。
5. **会话解析优先级**：`config.base_url` 非空 → 会话自带端点，Key 只取会话自己的（绝不取提供方的，防把管理员的 Key 发到用户指定的地址）；否则走提供方——`config.provider_id` 指名的，或未指名时的默认提供方，端点、模型、Key 都来自它，`config.model` 可覆盖模型。`provider_id` 与 `base_url` 同时出现即 `400`；`config.provider_id` 指向不存在的提供方时，发消息前给出 `UNAVAILABLE` 的明确文案。
6. **出站控制**：提供方端点上的所有请求（会话轮次与 `POST …/test`）都经 AGT-03 的受控客户端：私网默认拒绝，放行只来自 `agent.model_egress_allow`。`test` 只返回 `{ok, latency_ms?, category?}`（`auth|network|denied|4xx|5xx`），不回显地址、精确状态码与响应体。
7. **Agent 核心清单**：`GET /api/v1/agent-cores` 列出 ADR-0010 的四个核心与可用性；外部 CLI 由 P6 接入，现在返回 `available: false` 与固定原因。

## 后果

- 会话创建（`POST /agent-sessions`）的 `config` 新增可选 `provider_id`；`api_key_secret` 依旧 `400`。默认提供方在**发消息时**解析，会话不固定拷贝当时的默认值。
- 提供方动作是 human-only 且不进 AI 动作目录，提示注入的 agent 不能改端点；`GET /actions` 对其不可见。
- 删除提供方后仍引用它的会话在下次发消息时收到 `UNAVAILABLE`，用户改选其他提供方即可。

## 未采用

- **通用 secret CRUD**：任意引用即漏洞根因（AGT-02）；Key 只能按"属主资源"写入。
- **`api_key` 放进 create/update 请求体**：会经 operation 与幂等重放落库，明文留痕。
- **会话把默认提供方 id 固化到 config**：默认是"没指名时用哪个"的单一事实，固化会让改默认对老会话不生效。
- **非管理员的列表里给 `base_url`**：泄漏内网布局与端点指纹。
