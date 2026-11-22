# ADR-0014：插件 permission 命名规则与 manifest schema 1.2

- 状态：Accepted（2026-11-09，审查任务卡 SDK-04）
- 关联：ADR-0004、ADR-0007（ABI 冻结）、ADR-0010、ARCH §5.3

## 背景

鉴权只看 permission 字符串：viewer 对 action 属于 `read/list/get/export/describe/watch` 的任何权限都放行。manifest 却没有约束 permission：`effect:"write"` 可以配 `acme:read`，资源段可以写 `host.nodes`，插件 id 甚至可以是 `host`。结果是一个签名插件能让 viewer 或只读委托免确认执行写操作。

## 决策

1. **资源段归属**：`operations[].permission` 与 `ui.routes[].permission` 的资源段必须等于插件 id，或以 `插件id.` 开头（错误码 `PERMISSION_NAMESPACE`）。
2. **效果匹配**：`effect != read` 的操作不得使用只读类 action（`PERMISSION_EFFECT_MISMATCH`）。反向不限制：只读操作可以用 `run` 等 action 收紧授权。
3. **保留 id**：`host`、`qwq` 及其 `.` 子命名空间不得作插件 id（`PLUGIN_ID_RESERVED`）。所有 schema minor 一律执行：这些命名空间从未分配给插件，没有兼容负担。
4. **schema 1.2**：结构与 1.1 相同，只是规则 1、2 从 1.2 起强制。1.0、1.1 包可能已签名，继续接受。规则体系没有 warning 级别，所以旧 minor 不输出告警。
5. **唯一的只读表**：SDK 导出 `manifest.ReadOnlyActions`，宿主 `authz.isReadPermission` 引用它，两边不再漂移。Python 校验器 `tools/manifest_check.py` 同步持有同一份列表，由共享夹具对照。
6. **运行时纵深防御**：对任何 schema 版本的插件动作，`effect != read` 且 permission 为只读类 action 时，宿主改为检查 `<资源段>:write`，viewer 与只读委托因此被拒，admin/operator 不受影响。

7. **自 2026-11-09 起拒绝旧 minor**：宿主对 `schema_version` < 1.2 的新安装和更新返回 `VALIDATION_FAILED` + `SCHEMA_VERSION_TOO_OLD`（目前只有首方插件，已全部升到 1.2）。已安装的旧版本继续运行，宿主启动时记一条 WARN。SDK 解析仍接受 1.0/1.1。

## 后果

- 旧 minor 绕开规则 1 的口子由决策 7 关闭；只剩此前已安装的旧版本，规则 6 仍为其兜底。
- 示例 manifest 升到 1.2，`scan.run` 改用 `security.scan:read`。
- 旧宿主（最高支持 1.1）拒绝 1.2 manifest，这是 schema 版本规则的预期行为。

## 未采用

- 为旧 minor 增加 warning 级别：需要改 `Violation` 与安装 API 的响应，收益只是一段过渡期提示。
- 直接拒绝运行时不匹配的动作：会让已安装的旧插件连 admin 都无法使用；检查 `:write` 同样堵住了漏洞。
