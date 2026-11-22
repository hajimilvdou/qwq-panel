// SPDX-License-Identifier: AGPL-3.0-only

// Package pluginconfig 实现 ADR-0023 H2 受控跨插件配置读写能力（pluginconfig.v1）。
// 机密隔离铁律：GetConfig 将 {"$secret":"sec_..."} 脱敏为 {"$secret_present":true}；
// PutConfig 支持 {"$keep_secret":true} 由宿主原位继承目标插件既有密文引用，拒绝跨插件伪造引用。
package pluginconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	pluginconfigv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/pluginconfig/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ======================== 宿主配置管线窄接口 ========================

// Backend 抽象宿主对目标插件配置的读取与落盘管线（由 controller 注入）。
type Backend interface {
	GetPluginConfig(ctx context.Context, targetPluginID string) (configJSON []byte, revision string, err error)
	PutPluginConfig(ctx context.Context, targetPluginID string, configJSON []byte, expectedRevision string, triggerApply bool) (revision string, applyOpID string, err error)
}

// Forwarder 将 hostsvc 的 pluginconfig 能力调用路由至宿主本地 Backend。
type Forwarder struct {
	Backend Backend
}

// Forward 实现 hostsvc.CapabilityForwarder。
func (f Forwarder) Forward(ctx context.Context, call hostsvc.CapabilityCall) (hostsvc.CapabilityResult, error) {
	if f.Backend == nil {
		return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "跨插件配置服务尚未初始化")
	}
	switch call.Method {
	case "GetConfig":
		req, ok := call.Request.(*pluginconfigv1.GetConfigRequest)
		if !ok {
			return hostsvc.CapabilityResult{}, status.Error(codes.InvalidArgument, "无效的 GetConfig 请求")
		}
		return f.handleGet(ctx, req)
	case "PutConfig":
		req, ok := call.Request.(*pluginconfigv1.PutConfigRequest)
		if !ok {
			return hostsvc.CapabilityResult{}, status.Error(codes.InvalidArgument, "无效的 PutConfig 请求")
		}
		return f.handlePut(ctx, req)
	default:
		return hostsvc.CapabilityResult{}, status.Error(codes.Unimplemented, "不支持的 pluginconfig 方法")
	}
}

func (f Forwarder) handleGet(ctx context.Context, req *pluginconfigv1.GetConfigRequest) (hostsvc.CapabilityResult, error) {
	target := strings.TrimSpace(req.GetTargetPluginId())
	if target == "" {
		return domainFail("VALIDATION_FAILED", "target_plugin_id 不能为空"), nil
	}
	raw, rev, err := f.Backend.GetPluginConfig(ctx, target)
	if err != nil {
		code, msg := mapBackendError(err)
		return domainFail(code, msg), nil
	}
	redacted, err := RedactSecrets(raw)
	if err != nil {
		return domainFail("INTERNAL", "配置脱敏失败"), nil
	}
	return hostsvc.CapabilityResult{
		Response: &pluginconfigv1.GetConfigResponse{
			RedactedConfigJson: redacted,
			Revision:           rev,
		},
	}, nil
}

func (f Forwarder) handlePut(ctx context.Context, req *pluginconfigv1.PutConfigRequest) (hostsvc.CapabilityResult, error) {
	target := strings.TrimSpace(req.GetTargetPluginId())
	if target == "" || len(req.GetConfigJson()) == 0 {
		return domainFail("VALIDATION_FAILED", "target_plugin_id 与 config_json 必填"), nil
	}
	existingRaw, currentRev, err := f.Backend.GetPluginConfig(ctx, target)
	if err != nil {
		code, msg := mapBackendError(err)
		return domainFail(code, msg), nil
	}
	if req.GetExpectedRevision() != "" && currentRev != "" && req.GetExpectedRevision() != currentRev {
		return domainFail("PRECONDITION_FAILED", "配置 revision 冲突，请重新读取后再提交"), nil
	}
	merged, err := MergeKeptSecrets(existingRaw, req.GetConfigJson())
	if err != nil {
		return domainFail("VALIDATION_FAILED", err.Error()), nil
	}
	newRev, applyOpID, err := f.Backend.PutPluginConfig(ctx, target, merged, req.GetExpectedRevision(), req.GetTriggerApply())
	if err != nil {
		code, msg := mapBackendError(err)
		return domainFail(code, msg), nil
	}
	return hostsvc.CapabilityResult{
		Response: &pluginconfigv1.PutConfigResponse{
			Revision:         newRev,
			ApplyOperationId: applyOpID,
		},
	}, nil
}

func domainFail(code, msg string) hostsvc.CapabilityResult {
	return hostsvc.CapabilityResult{
		Error: &hostsvc.DomainError{Code: code, Message: msg},
	}
}

func mapBackendError(err error) (string, string) {
	var p *problem.Error
	if errors.As(err, &p) && p != nil {
		switch p.Code {
		case problem.NotFound:
			return "NOT_FOUND", p.Detail
		case problem.RevisionConflict, problem.PreconditionFailed, problem.StateConflict:
			return "PRECONDITION_FAILED", p.Detail
		case problem.ValidationFailed:
			return "VALIDATION_FAILED", p.Detail
		case problem.PermissionDenied:
			return "PERMISSION_DENIED", p.Detail
		default:
			return "UNAVAILABLE", p.Detail
		}
	}
	return "UNAVAILABLE", "目标插件配置操作失败"
}

// ======================== 机密引用脱敏与原位继承 ========================

func isSecretRefObject(m map[string]any) (string, bool) {
	if len(m) != 1 {
		return "", false
	}
	raw, ok := m["$secret"]
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	return s, ok && s != ""
}

func isKeepSecretObject(m map[string]any) bool {
	if len(m) != 1 {
		return false
	}
	v, ok := m["$keep_secret"]
	b, bok := v.(bool)
	return ok && bok && b
}

// RedactSecrets 将任意 JSON 中的 {"$secret":"sec_..."} 替换为 {"$secret_present":true}。
func RedactSecrets(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return []byte("{}"), nil
	}
	var doc any
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	return json.Marshal(redactNode(doc))
}

func redactNode(node any) any {
	switch v := node.(type) {
	case map[string]any:
		if _, ok := isSecretRefObject(v); ok {
			return map[string]any{"$secret_present": true}
		}
		out := make(map[string]any, len(v))
		for k, child := range v {
			out[k] = redactNode(child)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = redactNode(child)
		}
		return out
	default:
		return v
	}
}

// MergeKeptSecrets 将提交配置中的 {"$keep_secret":true} 替换为目标既有配置对应位置的 {"$secret":"..."}，
// 并阻止调用方注入不属于对应既有位置的任意 {"$secret":"..."} 引用。
// 对于按稳定 "id" 标识的对象数组（如 profiles/users），支持按 id 对齐继承原位机密！
func MergeKeptSecrets(existingRaw, proposedRaw []byte) ([]byte, error) {
	var existingDoc any
	if trimmed := bytes.TrimSpace(existingRaw); len(trimmed) > 0 {
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		if err := dec.Decode(&existingDoc); err != nil {
			return nil, fmt.Errorf("现有目标配置 JSON 无效: %w", err)
		}
	}
	var proposedDoc any
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(proposedRaw)))
	dec.UseNumber()
	if err := dec.Decode(&proposedDoc); err != nil {
		return nil, fmt.Errorf("提交配置 JSON 无效: %w", err)
	}
	merged, err := mergeNode(existingDoc, proposedDoc, "")
	if err != nil {
		return nil, err
	}
	return json.Marshal(merged)
}

func mergeNode(existing, proposed any, path string) (any, error) {
	switch p := proposed.(type) {
	case map[string]any:
		if isKeepSecretObject(p) {
			em, ok := existing.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("路径 %s 无既有密文可继承", path)
			}
			secID, ok := isSecretRefObject(em)
			if !ok {
				return nil, fmt.Errorf("路径 %s 既有字段不是有效密文引用", path)
			}
			return map[string]any{"$secret": secID}, nil
		}
		if secID, ok := isSecretRefObject(p); ok {
			em, eok := existing.(map[string]any)
			if !eok {
				return nil, fmt.Errorf("路径 %s 不允许跨插件伪造 $secret 引用", path)
			}
			oldID, oldOK := isSecretRefObject(em)
			if !oldOK || oldID != secID {
				return nil, fmt.Errorf("路径 %s 的 $secret 引用与既有值不匹配", path)
			}
			return map[string]any{"$secret": oldID}, nil
		}
		existingMap, _ := existing.(map[string]any)
		out := make(map[string]any, len(p))
		for k, child := range p {
			var eChild any
			if existingMap != nil {
				eChild = existingMap[k]
			}
			mergedChild, err := mergeNode(eChild, child, path+"/"+k)
			if err != nil {
				return nil, err
			}
			out[k] = mergedChild
		}
		return out, nil

	case []any:
		existingSlice, _ := existing.([]any)
		byID := indexSliceByID(existingSlice)
		out := make([]any, len(p))
		for i, item := range p {
			var eItem any
			if im, ok := item.(map[string]any); ok {
				if id, ok := im["id"].(string); ok && id != "" {
					if matched, found := byID[id]; found {
						eItem = matched
					}
				}
			}
			if eItem == nil && i < len(existingSlice) {
				eItem = existingSlice[i]
			}
			mergedItem, err := mergeNode(eItem, item, fmt.Sprintf("%s/%d", path, i))
			if err != nil {
				return nil, err
			}
			out[i] = mergedItem
		}
		return out, nil

	default:
		return p, nil
	}
}

func indexSliceByID(items []any) map[string]any {
	if len(items) == 0 {
		return nil
	}
	index := make(map[string]any, len(items))
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if id, ok := m["id"].(string); ok && id != "" {
			index[id] = m
		}
	}
	return index
}
