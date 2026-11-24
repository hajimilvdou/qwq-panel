// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/qwq-panel/qwq/internal/sandbox"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/state"
	"github.com/qwq-panel/qwq/sdk/coreapi"
	"github.com/qwq-panel/qwq/sdk/pluginsdk"
)

// ======================== 运行状态来源 ========================
// 持久 RUNNING 不能证明当前进程存活；真实进程管理器接入后复用同一接口。
type runtimeSource interface {
	Snapshot(context.Context) (runtimeSnapshot, error)
}

type runtimeSnapshot struct {
	metadata     *state.Metadata
	coreVersion  string
	processState string
	apiState     string
	lastError    string
	applying     bool
}

type statusResult struct {
	State           string `json:"state"`
	DriverState     string `json:"driver_state"`
	ProcessState    string `json:"process_state"`
	APIState        string `json:"api_state"`
	ProxyAvailable  bool   `json:"proxy_available"`
	Enabled         bool   `json:"enabled"`
	DesiredRevision string `json:"desired_revision,omitempty"`
	RunningRevision string `json:"running_revision,omitempty"`
	ConfigDigest    string `json:"config_digest,omitempty"`
	CoreVersion     string `json:"core_version"`
	ResetEpoch      string `json:"reset_epoch,omitempty"`
	LastError       string `json:"last_error,omitempty"`
}

func (i *instance) driverState() string {
	if current := i.State(); current == pluginsdk.StateActive || current == pluginsdk.StateReady {
		return "SERVING"
	}
	return "NOT_SERVING"
}

func (i *instance) readSnapshot(ctx context.Context) (runtimeSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return runtimeSnapshot{}, err
	}
	snapshot, err := i.runtime.Snapshot(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return runtimeSnapshot{}, ctx.Err()
		}
		if errors.Is(err, state.ErrCorrupt) {
			return runtimeSnapshot{}, pluginsdk.Errorf("SNAPSHOT_CORRUPT", "已提交的运行快照损坏，代理不可用")
		}
		return runtimeSnapshot{}, pluginsdk.Errorf("CORE_STATE_UNAVAILABLE", "代理状态暂不可用")
	}
	if snapshot.metadata != nil && snapshot.metadata.Validate() != nil {
		return runtimeSnapshot{}, pluginsdk.Errorf("SNAPSHOT_CORRUPT", "已提交的运行快照损坏，代理不可用")
	}
	return snapshot, nil
}

func (i *instance) readStatus(ctx context.Context) (statusResult, error) {
	snapshot, err := i.readSnapshot(ctx)
	if err != nil {
		return statusResult{}, err
	}
	result := statusResult{State: "UNCONFIGURED", DriverState: i.driverState(), CoreVersion: snapshot.coreVersion,
		ProcessState: snapshot.processState, APIState: snapshot.apiState}
	if result.ProcessState == "" {
		result.ProcessState = "STOPPED"
	}
	if result.APIState == "" {
		result.APIState = "UNAVAILABLE"
	}
	if desired := i.desired.Load(); desired != nil {
		result.DesiredRevision = desired.revision
		result.State = "PENDING_APPLY"
	}
	if committed := snapshot.metadata; committed != nil {
		result.RunningRevision, result.ConfigDigest = committed.Current.Revision, committed.Current.Digest
		result.Enabled, result.ResetEpoch, result.LastError = committed.Current.Enabled, committed.ResetEpoch, committed.LastError
		result.State = "STOPPED"
		if committed.State == "FAILED" {
			result.State = "FAILED"
		} else if committed.State == "STOPPED" {
			result.State = "STOPPED"
		} else if committed.Current.Enabled {
			switch {
			case result.ProcessState != "RUNNING":
				result.State, result.LastError = "FAILED", "CORE_EXITED"
			case result.APIState != "READY":
				result.State, result.LastError = "DEGRADED", "CORE_API_UNAVAILABLE"
			default:
				result.State, result.ProxyAvailable = "RUNNING", true
			}
		}
		if result.State != "FAILED" && result.State != "DEGRADED" && result.DesiredRevision != "" && result.DesiredRevision != result.RunningRevision {
			result.State = "PENDING_APPLY"
		}
	}
	if snapshot.lastError != "" {
		result.LastError = snapshot.lastError
		if snapshot.metadata == nil || snapshot.lastError == "RECOVERY_FAILED" {
			result.State, result.ProxyAvailable = "FAILED", false
		}
	}
	if snapshot.applying {
		result.State, result.ProxyAvailable = "APPLYING", false
	}
	return result, nil
}

func (i *instance) status(ctx context.Context, request pluginsdk.Request) (pluginsdk.Response, error) {
	if _, err := decodeReadInput(request.Payload, false); err != nil {
		return pluginsdk.Response{}, err
	}
	result, err := i.readStatus(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	return readResponse(result)
}

// ======================== 能力矩阵与纯校验 ========================
type capabilityUnavailable struct {
	Capability string `json:"capability"`
	Reason     string `json:"reason"`
}

type capabilitiesResult struct {
	DriverVersion string                  `json:"driver_version"`
	CoreVersion   string                  `json:"core_version"`
	SchemaVersion string                  `json:"schema_version"`
	ObfsAvailable bool                    `json:"obfs_available"`
	Declared      []string                `json:"declared"`
	Verified      []string                `json:"verified"`
	Unavailable   []capabilityUnavailable `json:"unavailable"`
}

func (i *instance) capabilities(ctx context.Context, request pluginsdk.Request) (pluginsdk.Response, error) {
	if _, err := decodeReadInput(request.Payload, false); err != nil {
		return pluginsdk.Response{}, err
	}
	snapshot, err := i.readSnapshot(ctx)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	version, err := packageVersion()
	if err != nil {
		return pluginsdk.Response{}, err
	}
	result := capabilitiesResult{
		DriverVersion: version,
		CoreVersion:   snapshot.coreVersion,
		SchemaVersion: "2",
		ObfsAvailable: i.driver != nil && i.driver.obfs != nil,
		Declared: []string{
			"vless_reality_vision_raw",
			"vless_ws_grpc_xhttp",
			"vmess",
			"trojan",
			"shadowsocks",
			"shadowsocks2022",
			"hysteria2",
			"anytls_v2",
			"socks5",
			"http",
			"warp_outbound",
			"direct_outbound",
			"private_uds",
			"stats_service",
			"per_user_mark",
			"tls_hot_reload",
		},
		Verified: []string{
			"native_render",
			"native_preflight",
			"private_uds",
			"stats_service",
			"missing_series_detection",
			"anytls_v2",
			"tls_hot_reload",
			"epoch_aligned_anytls_counters",
		},
		Unavailable: []capabilityUnavailable{},
	}
	if i.driver == nil {
		result.Unavailable = append(result.Unavailable, capabilityUnavailable{"observe", "UNIMPLEMENTED"})
	}
	if i.driver == nil {
		result.Unavailable = append(result.Unavailable, capabilityUnavailable{"apply", "UNIMPLEMENTED"})
	}
	if i.driver != nil && !i.driver.trusted {
		result.Unavailable = append(result.Unavailable, capabilityUnavailable{"apply", "CORE_BINARY_MISMATCH"})
	}
	if snapshot.coreVersion == "" {
		result.Unavailable = append(result.Unavailable, capabilityUnavailable{"core_binary", "CORE_BINARY_UNAVAILABLE"})
	}
	return readResponse(result)
}

type validateResult struct {
	ConfigRevision           string              `json:"config_revision,omitempty"`
	Valid                    bool                `json:"valid"`
	NativePreflightPerformed bool                `json:"native_preflight_performed"`
	Violations               []coreapi.Violation `json:"violations"`
	Warnings                 []coreapi.Violation `json:"warnings"`
}

func (i *instance) validate(ctx context.Context, request pluginsdk.Request) (pluginsdk.Response, error) {
	revision, err := decodeReadInput(request.Payload, true)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	data, actual, err := i.loadConfig(ctx, request, revision)
	if err != nil {
		return pluginsdk.Response{}, err
	}
	result := validateResult{ConfigRevision: actual, Violations: []coreapi.Violation{},
		Warnings: []coreapi.Violation{{Pointer: "", Code: "NATIVE_PREFLIGHT_NOT_RUN", Message: "仅执行静态校验；原生预检在 Apply 时执行"}}}
	_, _, err = decodeDesired(data)
	if err == nil {
		result.Valid = true
	} else {
		var failure *pluginsdk.Error
		if !errors.As(err, &failure) {
			return pluginsdk.Response{}, pluginsdk.Errorf("INVALID_INTENT", "Core Intent 配置无效")
		}
		for _, violation := range failure.Violations {
			pointer := violation.Pointer
			// 未知键名来自输入，不能把可能藏在键名里的秘密带到响应。
			if violation.Code == "UNKNOWN_FIELD" || violation.Code == "DUPLICATE_KEY" {
				pointer = ""
			}
			result.Violations = append(result.Violations, coreapi.Violation{Pointer: pointer, Code: violation.Code, Message: violation.Message})
		}
	}
	return readResponse(result)
}

// loadConfig 优先读取宿主版本库；没有 Host 的测试只允许读取已知内存版本。
func (i *instance) loadConfig(ctx context.Context, request pluginsdk.Request, revision string) ([]byte, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if host := request.Host(); host != nil && host.Conn() != nil {
		data, actual, err := host.GetConfig(ctx, revision)
		if err != nil {
			if ctx.Err() != nil {
				return nil, "", ctx.Err()
			}
			var failure *pluginsdk.Error
			if revision != "" && errors.As(err, &failure) && failure.Code == "NOT_FOUND" {
				return nil, "", pluginsdk.Errorf("CONFIG_REVISION_NOT_FOUND", "指定的期望配置版本不存在")
			}
			return nil, "", pluginsdk.Errorf("CONFIG_UNAVAILABLE", "期望配置暂不可用")
		}
		if revision != "" && revision != actual {
			return nil, "", pluginsdk.Errorf("CONFIG_REVISION_NOT_FOUND", "指定的期望配置版本不存在")
		}
		if actual != "" && !state.ValidRevision(actual) {
			return nil, "", pluginsdk.Errorf("CONFIG_UNAVAILABLE", "期望配置版本无效")
		}
		return data, actual, nil
	}
	desired := i.desired.Load()
	if desired == nil {
		if revision != "" {
			return nil, "", pluginsdk.Errorf("CONFIG_REVISION_NOT_FOUND", "指定的期望配置版本不存在")
		}
		return nil, "", nil
	}
	if revision != "" && revision != desired.revision {
		return nil, "", pluginsdk.Errorf("CONFIG_REVISION_NOT_FOUND", "指定的期望配置版本不存在")
	}
	var target any = desired.intent
	if desired.intentV2 != nil {
		target = desired.intentV2
	}
	data, err := json.Marshal(target)
	if err != nil {
		return nil, "", pluginsdk.Errorf("CONFIG_UNAVAILABLE", "期望配置暂不可用")
	}
	return data, desired.revision, nil
}

// decodeReadInput 复用宿主严格 JSON 检查，只开放当前 operation 的有限字段。
func decodeReadInput(payload []byte, allowRevision bool) (string, error) {
	invalid := func() (string, error) {
		return "", pluginsdk.Errorf("INVALID_REQUEST", "请求字段或配置版本无效")
	}
	if len(payload) > 1024 {
		return invalid()
	}
	if len(bytes.TrimSpace(payload)) == 0 {
		payload = []byte(`{}`)
	}
	var fields map[string]json.RawMessage
	if sandbox.DecodeHelperDocument(payload, &fields) != nil {
		return invalid()
	}
	if len(fields) == 0 {
		return "", nil
	}
	if !allowRevision || len(fields) != 1 || fields["config_revision"] == nil {
		return invalid()
	}
	var revision string
	if json.Unmarshal(fields["config_revision"], &revision) != nil || !state.ValidRevision(revision) {
		return invalid()
	}
	return revision, nil
}

func readResponse(result any) (pluginsdk.Response, error) {
	payload, err := json.Marshal(result)
	if err != nil {
		return pluginsdk.Response{}, pluginsdk.Errorf("CORE_STATE_UNAVAILABLE", "代理响应暂不可用")
	}
	return pluginsdk.Response{Payload: payload}, nil
}
