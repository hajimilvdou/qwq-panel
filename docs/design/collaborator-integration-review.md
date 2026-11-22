# 协作者提交集成复核

2026-11-21，冻结复核 `b47c615a469a0f03daceca5672b81fdea83f47a2`。Root 只选取兼容与安全小修，前端样式、agent/CLI 适配继续由协作者维护；未整包合入，也未 push。

## 本次选取

| 文件 | 行为 | 依赖与验证 |
|---|---|---|
| `web/shell/src/lib/drafts.ts` | 数组和数组中的对象逐层剔除秘密字段 | 不变更接口；普通值、数组结构和原输入保持 |
| `web/shell/src/ui/schema-form.ts` | 兼容现有后端的 `x-secret` | 复用原秘密字段状态、引用保留、显式替换与草稿过滤 |

两份生产文件与协作者冻结 Git blob 完全相同。新增两项集成回归验证实际草稿与配置提交路径，没有修改前端布局或新增依赖。

## 保留在协作者分支的阻断

- **P0：生产非 root CLI 身份。** controller 使用 `User=qwq`，launcher 非 root 分支仍允许同 UID 进程读取宿主 0600 文件；root 降 nobody 的正例不能证明生产隔离。
- **P1：CLI 回收与 MCP。** 进程组回收超时/kill 错误没有传播，数字 PGID 复用未关闭；stdio 请求绕过 HTTP MCP 额度；Claude MCP 配置文件未归入子进程可读的受控身份目录。
- **P1：kit/host 桥。** 已 aborted 请求在登记前取消导致 Promise 永久等待；接收 `plugin.port` 未校验父窗口；旧 invoke 结果可能发给 attach 后的新连接并命中重复的 `kit_1`。Root 与唯一代理分别读取确认，未将正向握手测试当成负向门禁。
- **P1：Markdown URL。** 直接执行冻结实现，`"/" + "\t" + "\\" + "example.invalid/path"` 被放行，URL 归一后跳至外部源；仅检查紧邻反斜杠及 CR/LF 不足。
- **权限组合待收口。** 两个 Tab 的权限名需要与角色映射一起提交；冻结角色表比 SDK 只读动作多 `logs/discover`、少 `watch`，并遗漏 `host.account` 本人写例外。
- **调用闭环待收口。** `createFormIntent` 未被实际表单调用；安装向导未按 `OpResult.status` 区分后台运行。真实 CLI、外部 core 压缩、异步 CORE05 尚未完整验收。

SDK 的克隆失败清理、响应超时、订阅主题释放/上限与 UTF-8 帧预算另按 P2 反馈；详情保留在共享消息文件。以上文件没有在本批选取，不能据本批测试声称整包通过。

## Linux 证据

- 首次入口完整 exit 1：远端缺少 `web/vitest.config.ts`，默认 Vite root 导致未找到测试；下一次先校验配置，明确发现该文件缺失。两份失败记录保留。
- 仅失效该文件的增量清单条目并补传，未 full 回退。`collaborator-secrets-red-resync-retry2-20261121` 完整 exit 1：两项业务回归均真实失败，分别保留数组内秘密和将 `x-secret` 当普通字段。
- `collaborator-secrets-green-20261121` 完整 exit 0：相同两项回归和原 `lib/fe-c` 回归，共 **23/23** 通过；`svelte-check` 0 errors/0 warnings，TypeScript 检查通过。
- Linux Node `v22.23.5` 使用已有项目工具及校验记录；没有安装依赖或运行本机工具链。3 源冻结清单 SHA256：`4bafd4c5508464553c3693bd0da6880d587930e98262aab347400fc11a07a33b`。
- Markdown 负例已直接执行协作者源码，日志确认 `collaborator_markdown_tab_external_origin=confirmed`。域名、引用与值均为测试夹具。

原始日志和源清单位于 `wt-host-core/.cache/collaborator-secrets-*`。测试未启动开发服务器，远端命令和本机 rrun 临时目录已收完整终态并清理；Vite 的未来配置加载方式提示不影响当前检查结果。

## Root P0/P1/P2 自检

本次选取范围未发现 P0/P1/P2 阻断：复用既有秘密字段模型与过滤规则，没有改变后端授权、函数签名、配置引用归属或操作链。回归确认输入未突变、秘密不入草稿、未替换保留原引用、仅显式替换提交新值。仍按项目总计划继续真实插件/客户端、双 VPS 和 1C1G 24 小时验收；本批不勾选整体 Track 07 或 CORE05。
