# 参与贡献

## 许可证与 CLA

本仓库按目录分区许可（[ADR-0005](docs/adr/0005-project-baseline-decisions.md)，明细见 [NOTICE](NOTICE)）：

| 部分 | 许可证 |
|---|---|
| `api/`（proto、manifest schema、OpenAPI）、`sdk/`（独立 Go 模块）、`web/kit/` | Apache-2.0 |
| 其余全部（`cmd/`、`internal/`、`web/shell/`、内置插件、脚本） | AGPL-3.0-only；版权持有人另行提供商业授权 |

- 插件只需依赖 `sdk/` 模块，可以使用任何许可证（包括闭源）。`sdk/` 不得导入宿主模块，`scripts/check.sh` 会检查。
- 双许可要求版权持有人能对全部代码重新授权，因此**外部贡献合并前必须签署贡献者许可协议（CLA）**。CLA 文本与签署流程在接受第一个外部 PR 之前公布（`IMPLEMENTATION-PLAN.md` Q9，需律师审阅）。在此之前不合并外部代码，欢迎提 issue 和参与讨论。
- 每个源文件开头带 SPDX 头，与所在目录的许可证一致：`// SPDX-License-Identifier: AGPL-3.0-only` 或 `// SPDX-License-Identifier: Apache-2.0`（shell、Python 用 `#`，CSS 用 `/* */`）。

## 开发环境

开发机上不全局安装任何工具（`IMPLEMENTATION-PLAN.md` §2）。编译、测试与代码生成在 Linux 构建机上进行，本机只需要 git、ssh、tar（文档类检查另需 python 与 node）：

```bash
cp scripts/remote.env.example scripts/remote.env   # 填写构建机地址与私钥路径（不提交）
bash scripts/remote.sh bootstrap                   # 安装 scripts/tools.lock 与 tools/ 锁定的工具链
bash scripts/remote.sh run bash scripts/check.sh   # 同步工作区并运行全部门禁
bash scripts/remote.sh pull sdk/gen                # 取回构建机上生成的文件
```

在 Linux 机器上也可以直接开发：`source scripts/dev-env.sh && bash scripts/bootstrap-tools.sh`，工具与缓存都在仓库内的 `.tools/`、`.cache/`。

仓库有两个 Go 模块：根模块 `github.com/qwq-panel/qwq`（宿主）与 `sdk/` 模块 `github.com/qwq-panel/qwq/sdk`。根 `go.mod` 用 `replace` 指向本地 `sdk/`，`go.work` 供编辑器联调，两种方式都能构建。`tools/` 与 `tools/buf/` 是只锁定开发工具版本的模块，不进入产品构建。

## 提交前

- `scripts/check.sh` 通过（`go vet`、staticcheck、两个模块的测试、govulncheck、`buf lint`/`buf breaking`、生成代码无漂移、manifest 校验、SPDX 与模块边界、交叉编译）。
- 自查 HANDOFF §1.3 的四个问题与 §11.4 评审项；遵守 ADR-0004 的三条纪律：没有只存在于前端的业务逻辑、不绕过 operation 写数据、每次写入都发事件。
- 改动 proto、manifest、权限模型或数据所有权，先写 ADR。新增依赖要回答 HANDOFF §1.3 的四个问题并核对许可证。
- 每个任务带测试。

## 分支与提交

- `main` 受保护；功能分支 + PR，squash 合并。
- 提交信息：`类型: 摘要`，类型取 `feat`、`fix`、`refactor`、`perf`、`test`、`docs`、`build`、`ci`、`chore`。正文写动机与影响面。
- 安全问题不要提公开 issue；发布前会在 `SECURITY.md` 中给出私下报告方式。
