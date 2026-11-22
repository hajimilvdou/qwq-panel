# DNC StateDirectory 实际属主验证

本步只核消费者能否读取宿主写入的 0600 文件。2026-11-21 的真实 Linux 结果为 legacy ownership 阳性：DynamicUser UID 为 62431，宿主 backing UID/GID 均为 62431，`mapped=false`。不能据此勾选 idmap、证书部署或运行时健康验收。

## 探针与证据

`tests/systemd/consumer_state_identity.py` 创建本次随机命名的 DynamicUser/StateDirectory 单元，使用 0700 状态目录、32M 内存、8 Tasks、25 秒 RuntimeMax 和私有网络。宿主从实际状态目录 FD 读取 UID/GID，先写 O_EXCL 临时文件，再按该属主移交、fsync 和原子发布；没有修改状态目录的属主。

动态用户成功读取 backing owner 的 0600 无秘密哨兵，并被 root 属主的 0600 负对照拒绝。结束和异常路径只停止描述符匹配的自有单元，确认单元及客户端终态后，删除本次四个固定普通单链接文件和空目录；不递归删除，不触碰现有插件状态。

- 原生日志：`.cache/dnc-state-identity-native-first-20261121.log`，完整 exit 0，`state_identity=pass` 和 `native_owned_state_cleanup=pass`。
- 原生入口 SHA256：`d85b5a417215e1e22e51b6c91c1df518c878a321cd613e6b38773037a1ddc3b2`。
- 探针源码 SHA256：`c47ac563ded115732b3866a110f0c8eb5bcb1fedc7b3701105134dfecb615d71`。
- Linux AST 与 repo_lint：`.cache/dnc-state-identity-syntax-20261121.log`，完整 exit 0。本步没有运行 Go 工具链或恢复延期中的 perf Go 探针。

## 后端接线依据

消费者文件后端必须捕获可信 StateDirectory FD 的实际 backing UID/GID。逻辑 `Consumer.ProfileID` 不充当 systemd 实例路径，`LoadCredential` 的启动时副本不充当 TLS 热更新。

这条证据只覆盖 legacy 权限映射。idmap namespace、窄特权 helper 的固定读写根、可信单代材料证明、当前授权和引用删除排他、热应用/健康/精确回滚及首次 H2 字节通信继续待验。当前没有本步启动的临时服务或 Linux session 待回收。

Root 已按自有资源边界、输入校验、错误收尾和证据范围做 P0/P1/P2 自检，未发现本探针的确定阻断；唯一既有代理的独立只读复核另记，不将其复核替代真实结果。
