# ADR-0018：manifest schema 1.3：概览小组件与可达性标记

- 状态：Accepted（2026-11-11，阶段 2 后端缺口 3、5、7）
- 关联：ADR-0007（ABI 冻结）、ADR-0010、ADR-0014、ARCH §5.3、§5.5；可达性操作的审批下限由同批的可达性 ADR 规定

## 背景

Web Shell 的主页要展示插件数据（CPU、安全体检、最近备份）。让每张卡片各开一个沙箱 iframe，1C1G 上开销大，主页还会运行不可信代码。另一件事：会切断管理通道的操作（防火墙、SSH、面板端口或 TLS）需要被宿主和界面识别出来，才能显示"可能导致无法连接服务器"并套用审批下限，而 manifest 没有地方声明。

两者都只是 manifest schema 的 minor 增量。Platform ABI（proto）不变：`PluginDescriptor` 不携带这两项，宿主本来就以验签后的 manifest 为准（ARCH §5.3）。

## 决策

1. **schema 1.3** 新增两个可选成员：`ui.widgets[]` 与 `operations[].reachability`。1.0～1.2 的 manifest 仍然有效；新安装与更新的下限仍是 1.2（ADR-0014 决策 7）。
2. **小组件**：`{id, title(≤32), kind, operation, refresh_seconds(2～86400), size, icon?, color?}`，每个插件最多 16 个。`kind` 为 `stat | series | checks | list`，固定了结果的形状；Shell 按形状校验后原生渲染，非法结果只让这一张卡片报错。`size` 为 `s | m | l`。`icon` 是 Shell 的图标名，未知名回落到 `kind` 的默认图标；`color` 取 Shell 的分类色枚举。
3. **小组件的数据来源**：`operation` 必须是本插件已声明、`effect=read` 且 `mode=invoke` 的操作（`UI_WIDGET_OPERATION_UNKNOWN`、`UI_WIDGET_OPERATION_UNSUITABLE`），`id` 不重复（`UI_WIDGET_DUPLICATE`）。Shell 以空 payload `{}` 轮询，所以该操作的 request schema 必须接受 `{}`；这一项要读包内文件，由宿主在安装时检查，不是 SDK 规则。读操作不产生 operation 记录，轮询不会让表增长。
4. **可达性标记**：`reachability: true` 的操作必须 `effect` 为 `write` 或 `destructive`、`risk: high`，且不得声明 `approval: auto`。写在 schema 的 `if/then` 里，与"`destructive` 必须 `risk: high`"是同一做法。作者必须如实定级；宿主另外按能力名强制置真并钳制下限，两层互不替代。
5. **版本如实**：1.3 新增的成员出现在声明更低 minor 的 manifest 里，返回 `SCHEMA_VERSION_TOO_LOW`。只看成员是否存在，不看取值。只支持到 1.2 的宿主会把它们当未知字段拒绝；新宿主若放行，`schema_version` 就不再能说明哪些宿主装得上这个包。
6. Python 校验器 `tools/manifest_check.py` 同步实现规则 3、5，由共享夹具对照。

## 后果

- 只支持到 1.2 的旧宿主拒绝 1.3 manifest，这是 schema 版本规则的预期行为。
- `widgets` 在 `ui` 之内，而 `ui` 要求 `entry`：只提供小组件的插件也得带一个入口页。
- schema 保证轮询间隔不低于 2 秒；宿主仍按"用户 + 小组件"限流，不信任客户端的节奏。

## 未采用

- 小组件用 iframe 渲染：见背景。
- 在 proto 的 `OperationDescriptor` 上加字段：要追加 ABI minor，而宿主并不读它。
- 宿主静默钳制作者的声明而不拒绝：安装向导展示的是 manifest，声明与实际执行不一致会误导用户。
- `widgets` 放在 manifest 顶层：小组件是界面贡献点，公共 API 的 `Plugin.ui` 也按此组织。
