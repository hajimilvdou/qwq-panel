// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/qwq-panel/qwq/internal/xraycore/state"
	"github.com/qwq-panel/qwq/sdk/coreapi"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

//go:embed manifest.json
var manifestJSON []byte

// Manifest 返回独立副本，避免调用方修改嵌入的描述符。
func Manifest() []byte { return append([]byte(nil), manifestJSON...) }

// packageVersion 与编译器嵌入的 manifest 共用身份；发布构建可通过 BuildVersion 注入。
var packageVersion = sync.OnceValues(func() (string, error) {
	if pluginsdk.BuildVersion != "" {
		return pluginsdk.BuildVersion, nil
	}
	parsed, err := manifest.Parse(Manifest())
	if err != nil {
		return "", pluginsdk.Errorf("INVALID_MANIFEST", "驱动包身份无效")
	}
	return parsed.Version, nil
})

// Plugin 通过实例工厂提供运行状态；每个实例独立持有自己的状态来源。
type Plugin struct {
	runtimeFactory func(string) runtimeSource
	driverFactory  func(*instance) (*driverRuntime, error)
	onFailure      func(error)
}

// New 创建插件，状态只属于后续创建的实例。
func New() *Plugin { return &Plugin{} }

// NewInstance 保存 desired，注册只读接口；进程切换仍只属于后续 Apply。
func (p *Plugin) NewInstance(ctx context.Context, info pluginsdk.InstanceInfo) (pluginsdk.Instance, error) {
	if info.StateSchemaVersion != "" && info.StateSchemaVersion != "1" {
		return nil, pluginsdk.Errorf("INCOMPATIBLE_STATE_SCHEMA", "运行快照版本不兼容")
	}
	inst := &instance{InstanceBase: pluginsdk.NewInstanceBase(info), fail: p.onFailure}
	if p.runtimeFactory != nil {
		inst.runtime = p.runtimeFactory(info.DataDir)
	} else {
		factory := p.driverFactory
		if factory == nil {
			factory = newDriverRuntime
		}
		driver, err := factory(inst)
		if err != nil {
			return nil, err
		}
		inst.runtime, inst.driver = driver, driver
	}
	initial := bytes.TrimSpace(info.Config)
	if len(initial) != 0 && !bytes.Equal(initial, []byte("{}")) {
		if err := inst.ApplyConfig(ctx, pluginsdk.Config{JSON: initial, Revision: info.ConfigRevision}); err != nil {
			return nil, err
		}
	}
	inst.HandleInvoke("core.capabilities", inst.capabilities)
	inst.HandleInvoke("core.validate", inst.validate)
	inst.HandleInvoke("core.status", inst.status)
	inst.HandleInvoke("core.observe", inst.observe)
	inst.HandleInvoke("core.export_client", inst.exportClient)
	inst.HandleInvoke("tls.reload", inst.tlsReload)
	inst.HandleInvoke("tls.inspect", inst.tlsInspect)
	inst.HandleJob("core.apply", inst.apply)
	inst.HandlePlan("core.apply", inst.plan)
	return inst, nil
}

// ======================== 不可变 desired 快照 ========================
// Intent 与 revision 在同一个原子指针中提交，读者不会混用两次配置。
type desiredSnapshot struct {
	intent   *coreapi.Intent
	intentV2 *corev2.Intent
	revision string
}

type instance struct {
	*pluginsdk.InstanceBase
	desired atomic.Pointer[desiredSnapshot]
	runtime runtimeSource
	driver  *driverRuntime
	fail    func(error)
}

// ValidateConfig 仅执行严格解码和纯语义校验。
func (*instance) ValidateConfig(ctx context.Context, config pluginsdk.Config) (pluginsdk.ConfigValidation, error) {
	if err := ctx.Err(); err != nil {
		return pluginsdk.ConfigValidation{}, err
	}
	_, _, err := decodeDesired(config.JSON)
	return pluginsdk.ConfigValidation{}, err
}

// ApplyConfig 仅替换内存期望态，不启动、停止、渲染或揭示任何内容。
func (i *instance) ApplyConfig(ctx context.Context, config pluginsdk.Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	intent, intentV2, err := decodeDesired(config.JSON)
	if err != nil {
		return err
	}
	revision := config.Revision
	if revision == "" {
		revision = config.CurrentRevision
	}
	if !state.ValidRevision(revision) {
		return pluginsdk.Errorf("INVALID_CONFIG_REVISION", "期望配置版本无效")
	}
	i.desired.Store(&desiredSnapshot{intent: intent, intentV2: intentV2, revision: revision})
	return nil
}

func decodeDesired(data []byte) (*coreapi.Intent, *corev2.Intent, error) {
	var head struct {
		SchemaVersion string `json:"schema_version"`
	}
	if json.Unmarshal(data, &head) == nil && head.SchemaVersion == "2" {
		intentV2, err := corev2.Decode(data)
		if err == nil {
			err = corev2.Validate(intentV2)
		}
		if err == nil {
			return nil, intentV2, nil
		}
		return nil, nil, mapIntentError(err)
	}
	intent, err := coreapi.Decode(data)
	if err == nil {
		err = coreapi.Validate(intent)
	}
	if err == nil {
		return intent, nil, nil
	}
	return nil, nil, mapIntentError(err)
}

func mapIntentError(err error) error {
	var failure *coreapi.Error
	if !errors.As(err, &failure) {
		return pluginsdk.Errorf("INVALID_INTENT", "Core Intent 配置无效")
	}
	violations := make([]pluginsdk.FieldViolation, len(failure.Violations))
	for index, violation := range failure.Violations {
		violations[index] = pluginsdk.FieldViolation{Pointer: violation.Pointer, Code: violation.Code, Message: violation.Message}
	}
	return &pluginsdk.Error{Code: "INVALID_INTENT", Message: "Core Intent 配置无效", Violations: violations}
}

// ======================== 生命周期与诚实健康信息 ========================
// SDK 负责实例状态机和后台取消；驱动只管理核心进程及私有提交快照。

// Start 只开放驱动 RPC，核心恢复在 Activate 执行。
func (*instance) Start(ctx context.Context) error { return ctx.Err() }

// Activate 只恢复已提交快照；无 current 时保持等待 Apply。
func (i *instance) Activate(ctx context.Context) error {
	if i.driver == nil {
		return nil
	}
	if err := i.Go(func(background context.Context) { <-background.Done(); i.driver.controller.Cancel() }); err != nil {
		return err
	}
	err := i.driver.activate(ctx)
	if host := i.Host(); err == nil && host != nil && host.Conn() != nil {
		err = i.driver.controller.SyncHost(ctx, host)
	}
	if err != nil {
		if i.fail != nil {
			i.fail(err)
		}
		return mapApplyError(err)
	}
	return nil
}

// Deactivate 取消事务并确认核心与 API 客户端已回收。
func (i *instance) Deactivate(ctx context.Context) error { return i.shutdown(ctx) }

// Stop 的请求排空由 SDK 管理。
func (i *instance) Stop(ctx context.Context) error { return i.shutdown(ctx) }

// Release 清除实例内存快照，宿主目录清理由正式卸载流程负责。
func (i *instance) Release(ctx context.Context) error {
	if err := i.shutdown(ctx); err != nil {
		return err
	}
	i.desired.Store(nil)
	return nil
}

func (i *instance) shutdown(ctx context.Context) error {
	if i.driver == nil {
		return nil
	}
	return mapApplyError(i.driver.controller.Deactivate(ctx))
}

// Health 与 core.status 读取同一来源；SDK 的 SERVING 只表示驱动 RPC 可用。
func (i *instance) Health(ctx context.Context) pluginsdk.Health {
	details, err := i.readStatus(ctx)
	if err != nil {
		code := "CORE_STATE_UNAVAILABLE"
		var failure *pluginsdk.Error
		if errors.As(err, &failure) {
			code = failure.Code
		}
		details = statusResult{State: "FAILED", DriverState: i.driverState(), ProcessState: "UNKNOWN", APIState: "UNAVAILABLE", LastError: code}
	}
	data, err := json.Marshal(details)
	if err != nil {
		return pluginsdk.Health{Message: "代理状态不可用"}
	}
	message := "代理尚未运行"
	if details.LastError == "SNAPSHOT_CORRUPT" {
		message = "运行快照损坏，代理不可用"
	} else if details.State == "DEGRADED" {
		message = "代理进程仍在运行，私有 API 不可用"
	} else if details.State == "PENDING_APPLY" && details.ProxyAvailable {
		message = "代理运行旧配置，等待应用最新期望版本"
	} else if details.ProxyAvailable {
		message = "代理正在运行"
	}
	return pluginsdk.Health{Message: message, Details: data}
}

func skeletonError() error { return pluginsdk.Errorf("UNIMPLEMENTED", "Xray 业务尚未实现") }
