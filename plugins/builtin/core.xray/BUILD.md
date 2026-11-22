# core.xray 候选包构建

只在既有 Linux 构建机的仓库根目录运行；Windows 和测试机不编译。显式设置既有签名私钥与公开信任根，工具不会生成默认私钥。私钥必须是 0600 普通文件，始终留在构建机。

```bash
export GOWORK=off
export QWQ_XRAY_SIGNING_KEY='<既有测试发布者私钥路径>'
export QWQ_XRAY_TRUST_PUB='<匹配的公开信任根路径>'
go run plugins/builtin/core.xray/build.go -version 0.1.1
go run plugins/builtin/core.xray/build.go -version 0.1.2
```

输入 Xray 固定为 `26.11.9`，二进制 SHA-256 必须等于 `e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d`；默认缓存路径 `.cache/core-xray/v26.11.9/unpacked/xray`，也可用 `-xray` 指定已核验公共备份。不会自动下载核心。

工具生成 `.cache/core-xray/out/core.xray-<version>.qwq`、摘要和 `key.pub`。源码 manifest 保持不变；Go overlay 给编译器提供本次版本与发布者，打包前验证实际嵌入的 manifest 和 RPC descriptor。候选包经过仓库 `qwqctl pack` → `sign` → `verify`，外部 manifest 的文件摘要由正式 pack 流程计算。

SBOM 记录实际驱动与核心二进制摘要、Go 链接依赖及来源；依赖许可证原文和修改过的 MPL Stats wire 源文件一起进入包。构建按已审查清单精确匹配模块路径、版本和 h1，并核验原文摘要；遇到未审查身份或许可即停止。第三方原文按上游字节保留。此构建步骤不代表真实安装、客户端或资源验收完成。

失败更新验收另构建专用故障包：

```bash
go run plugins/builtin/core.xray/build.go -version 0.1.3 -e2e-reject-core
```

该开关在核验原始核心后破坏副本的固定摘要，以验证签名正确但核心不可信的候选被拒绝并恢复旧版。包内构建记录标记故障注入；它仅用于 E2E，不得作为可运行候选发布。

真实验收需要 `QWQ_XRAY_E2E=1` 及专用签名包环境变量；普通测试不会启动 Xray/systemd。测试只在没有 qwq 安装的已授权隔离测试 VPS 执行，并由既有安装夹具在失败时也卸载清理。
