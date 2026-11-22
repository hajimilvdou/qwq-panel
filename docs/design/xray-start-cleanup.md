# Core 启动取消与失败清理

P1-PLG-03：Manager.Start 的取消分支取消 runner 后直接返回，调用方已退出而原 slot 仍清理；Activate 在 start 失败时未调用原 stopBounded。复用原 Manager slot/Track/Stop，不释放尚未清理的归属，也不新增进程管理器。

失败启动和请求取消共用有界 3 秒清理等待；超时返回原原因与 ErrStop，原 slot 继续阻止第二进程。Activate 在启动失败时用原独立 5 秒 stopBounded 清理；无法确认时明确报告 RECOVERY_FAILED，成功清理保留原 CORE_START_FAILED。原私有提交配置和正常启动后请求 context 不拥有进程运行期的契约保持。

真实 Manager/受跟踪 runner 以受控工厂延迟复现返回前未清理、等待超时归属和后续真实短时 Go 子进程启动；真实 Store/现有 Apply 夹具只替换进程边界，验证启动确认丢失后的清理、清理失败和可重试。所有控制 goroutine、定时器、runner 与子进程有明确退出边界。完整 Xray/VPS 实测另随业务终验。
