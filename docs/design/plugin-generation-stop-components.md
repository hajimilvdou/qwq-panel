# 固定代次停止组件

基线 80920f9ae65490785b3dadba21d2cda36839f494；工作树 wt-sec-runtime，分支 codex/plugin-generation-stop。

窄组件分批实现，Root统一Linux验证。此树不含core-xray的61源WIP，不复制旧归档。批次1：CgroupUnit纯规则移至sandbox，controller兼容wrapper；强ProcessProof/StopObservation与严格loaded profile parser。新版缺ExitType或任何必要字段拒绝；247/249仅按显式版本能力允许不存在ExitType，空值不会获默认授权。完成判断拒绝零proof、原主退出但旧组未知、替换cgroup。

批次2已实现固定proc目录FD相对读取、pidfd_open后原procFD signal0重核、pidfd自身fdinfo Pid映射确认、固定pidfd Signal/Poll、原cgroup目录与events双FD读取及互斥Close。生产Pin核动态非root四UID、两次实际profile/boot/ticks/InvocationID/cgroup及inode；版本或身份未知失败。仅原主退出不能生成全组完成；同一路径被新代次占据且原FD仍populated=1时安全失败。主pidfd已经确认的退出不可逆，后续取消/超时不覆盖这条原事实。

批次3已加入generation-observe/stop/retire独立typed协议、exact-key/presence/non-null、完整引用与canonical摘要。共用JSON分帧/reader/exchange，generation写请求前核真实root Unix peer；入口开始计共享预算，getter读取实际Manager.Version并核两份loaded元组。ProcessProof单源限制Linux int32 PID范围。请求/响应完整文档包括首尾空白共16KiB，写超限消息前不输出正文；其他旧helper协议仍1MiB。生产停止后端未装配，三verb返回Unavailable，不发送信号或写记录。

Root统一Linux验证已完成29源/28Go：60个typed/peer/预算/getter定向测试全部通过无skip，六包普通、四包race、静态/lint及qwq/privileged构建通过，Go格式归档逐成员/token/路径恢复。原组件真实内核分支仍通过；hybrid构建机v2只由测试显式选择/sys/fs/cgroup/unified，生产默认不降级。所有旧失败/原清单/归档保留，不push，不增加代理。

实际systemd255/kernel6.8探针确认PID1可在数毫秒内回收清空组，原eventsFD随后ENODEV且nlink不能证明删除；自动重启会同路径创建新inode/新MainPID。当前50ms轮询可能错过populated0，不把原主退出、路径消失、ENODEV或新主存在当原组完成。这个P1、实际helper CAP_KILL/seccomp/namespace、永久root见证落盘与所有五写出生proof/恢复/退休接线仍须解决，CORE05不因本组件通过而完成。独立P0/P1/P2及证据见ROOT-plugin-generation-components-20261121.md、ROOT-plugin-generation-protocol-20261121.md、ROOT-plugin-generation-kernfs-20261121.md。
