# 事件投递的授权与锁边界

实时投递和历史回放原来在持有 Hub 全局锁时调用 `Visibility`。生产授权读取当前角色、委托和资源归属，查询使用原有 2 秒超时；数据库等待会同时拖住统计、订阅入场和取消订阅。

## 最小实现

实时路径先在锁内复制当前候选订阅，锁外逐事件执行原动态授权；查询前后都在锁内核验 stopped、closed、closeRequested、live 和 resumeFrom，随后经共用 `deliverLocked` 非阻塞投递。channel 发送、满缓冲移除和关闭始终受同一锁保护，迟到结果不能重新激活已关闭的订阅。

回放同样在锁外逐事件授权，锁内投递并推进 replayNext。被拒绝的事件也推进水位，结束后按原逻辑转入 live 或补齐新尾部。现存订阅的回放字段只有唯一 tail loop 修改，不新增 CAS、并行授权或权限缓存；原 Actor、过滤和当前授权规则保持。

同时收口两个已核实的邻近问题：

- 无订阅时读取 HeadSeq 后，必须在锁内再次确认仍无订阅才推进 cursor。已有新订阅则从原 cursor 读日志，避免漏掉它入场后提交的事件。
- 决定缓冲溢出时先发布 overflow，再发日志通知并关闭 channel。消费者获知关闭后可立即读取准确的 buffer_overflow 原因。

唯一 tail loop 仍按序等待当前授权回调；Hub.Close 取得锁并取消运行后等待原回调结束，没有每事件新增 goroutine。订阅快照受现有 MaxSubscribers 约束。

## Linux 证据

- `event-visibility-lock-red-20261121` 完整 exit 1：实时/回放两条路径的统计、Close 四个受控回归均失败。用回调进入信号和释放 gate 固定窗口，没有靠 sleep 猜测持锁时间。
- `event-empty-head-red-20261121` 完整 exit 1：一次性 HeadSeq gate 固定空场检查；订阅以 head=1 入场后提交 seq=2，旧分支漏掉该事件。
- `event-overflow-publication-red-20261121` 完整 exit 1：测试 Logger 在明确的 drop 通知点读取到尚未发布的 overflow。该确定 RED 验证通知顺序；没有把调度碰运气的 close→Store 窗口宣称为确定复现。
- 最终 GREEN `event-visibility-final-green-20261121` 完整 exit 0：七个新边界和原可见性回归通过，涵盖迟到授权后的关闭、新订阅不丢不重、空场水位、溢出通知/关闭、拒绝回放推进及撤权后重新授权。
- events/controller/api 三包普通分别 0.812s/12.489s/18.439s；events 全包 race 1.840s，controller/API 的真实可见性及 SSE/事件回归 race 6.195s/3.671s。三包 vet/staticcheck、仓库 lint 和 CLI 构建通过。
- 3 Go 源冻结清单 `14d846c46ca4bfeb93ab98debf9519c92b130635c3f3db016da524196ac3e2de`；40960 bytes 格式归档 `4c160960b82dce474e127ca03234391ffed9752cdb722f00887cc2bb50cd5bb3` 已严格取回，成员/token/父路径/非 reparse 守卫通过。

所有命令与格式化仅 Linux。各轮失败、源清单、格式归档和完整日志保留在 `wt-host-core/.cache/event-*`；测试释放全部自有 gate/worker，rrun 与下载临时目录已清理。没有修改公共接口或迁移，不运行延期中的原组 perf Go 探针。

## Root P0/P1/P2 自检

本范围无遗留 P0/P1/P2 阻断：动态角色/归属仍逐次读取，锁外只访问不可变订阅字段；同锁重核与发送防止关闭竞态，单 tail 保持顺序，拒绝不堵住回放。空场读回后的再次检查保护新订阅，终态原因先于可观察通知和关闭。现有过滤、授权、回放/保留/溢出回归通过；不以这些组件测试替代完整双 VPS、客户端与 1C1G 24 小时终验。

唯一工程代理分别复核最终三文件和 SSE 关闭出口，P0/P1/P2 无确定问题；其只读结论与 Root 独立确认的完整 Linux 结果一致，未由代理执行或代替实际验证。
