// SPDX-License-Identifier: AGPL-3.0-only

package account

import (
	"context"
	"encoding/json"

	"github.com/qwq-panel/qwq/internal/capability/bridge"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/sandbox"
	accountv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/account/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ======================== Account Host Capability 转发器 ========================

// SecretRevealer 按当前已派发 operation 与插件身份揭示密码引用；插件全程不接触明文口令。
type SecretRevealer func(ctx context.Context, call hostsvc.CapabilityCall, secretRef string) ([]byte, error)

// Forwarder 转发经过能力门校验的 5 个 AccountService RPC。
type Forwarder struct {
	Helper       bridge.Caller
	RevealSecret SecretRevealer
}

func (f Forwarder) Forward(ctx context.Context, call hostsvc.CapabilityCall) (hostsvc.CapabilityResult, error) {
	if call.Service != "account" || f.Helper == nil {
		return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "账户能力执行器未接入")
	}
	switch call.Method {
	case "ListKeys":
		req, ok := call.Request.(*accountv1.ListKeysRequest)
		if !ok || req == nil {
			return invalidAccountCall()
		}
		if !validUserPattern.MatchString(req.GetUser()) {
			return validationAccountFailure("用户名格式无效")
		}
		return bridge.Invoke(ctx, f.Helper, call.PluginID, "account.list-keys", userQuery{User: req.GetUser()}, new(accountv1.ListKeysResponse))

	case "ImportKey":
		req, ok := call.Request.(*accountv1.ImportKeyRequest)
		if !ok || req == nil {
			return invalidAccountCall()
		}
		if !validUserPattern.MatchString(req.GetUser()) || req.GetPublicKey() == "" {
			return validationAccountFailure("导入公钥缺少合法用户名或公钥内容")
		}
		return bridge.Invoke(ctx, f.Helper, call.PluginID, "account.import-key", importKeyParams{
			User:             req.GetUser(),
			PublicKey:        req.GetPublicKey(),
			ExpectedRevision: req.GetExpectedRevision(),
		}, new(accountv1.ImportKeyResponse))

	case "RemoveKey":
		req, ok := call.Request.(*accountv1.RemoveKeyRequest)
		if !ok || req == nil {
			return invalidAccountCall()
		}
		if !validUserPattern.MatchString(req.GetUser()) || req.GetFingerprintSha256() == "" {
			return validationAccountFailure("删除公钥缺少合法用户名或指纹")
		}
		return bridge.Invoke(ctx, f.Helper, call.PluginID, "account.remove-key", removeKeyParams{
			User:             req.GetUser(),
			Fingerprint:      req.GetFingerprintSha256(),
			ExpectedRevision: req.GetExpectedRevision(),
		}, new(accountv1.RemoveKeyResponse))

	case "GenerateKey":
		req, ok := call.Request.(*accountv1.GenerateKeyRequest)
		if !ok || req == nil {
			return invalidAccountCall()
		}
		if !validUserPattern.MatchString(req.GetUser()) {
			return validationAccountFailure("生成密钥缺少合法用户名")
		}
		return bridge.Invoke(ctx, f.Helper, call.PluginID, "account.generate-key", generateKeyParams{
			User:             req.GetUser(),
			Type:             req.GetType(),
			ExpectedRevision: req.GetExpectedRevision(),
		}, new(accountv1.GenerateKeyResponse))

	case "SetPassword":
		req, ok := call.Request.(*accountv1.SetPasswordRequest)
		if !ok || req == nil {
			return invalidAccountCall()
		}
		if !validUserPattern.MatchString(req.GetUser()) || req.GetSecretRef() == "" {
			return validationAccountFailure("修改口令缺少合法用户名或密码引用")
		}
		if f.RevealSecret == nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Unavailable, "宿主口令秘密解引用未配置")
		}
		rawSecret, err := f.RevealSecret(ctx, call, req.GetSecretRef())
		if err != nil {
			return hostsvc.CapabilityResult{Error: &hostsvc.DomainError{Code: "PERMISSION_DENIED", Message: "无法解引用受保护口令材料"}}, nil
		}
		defer clear(rawSecret)

		password := decodePasswordSecret(rawSecret)
		defer clear(password)
		if !validPassword(password) {
			return validationAccountFailure("口令长度须在 12..128 字节之间且不含控制字符或冒号")
		}
		paramsJSON, err := json.Marshal(setPasswordParams{
			User:             req.GetUser(),
			ExpectedRevision: req.GetExpectedRevision(),
		})
		if err != nil {
			return hostsvc.CapabilityResult{}, status.Error(codes.Internal, "口令请求编码失败")
		}
		defer clear(paramsJSON)

		capReq := sandbox.CapabilityRequest{
			Op:         "account.set-password",
			ID:         call.PluginID,
			ParamsJSON: paramsJSON,
			Secret:     append([]byte(nil), password...),
		}
		defer clear(capReq.Secret)
		return bridge.Exchange(ctx, f.Helper, capReq, new(accountv1.SetPasswordResponse))

	default:
		return hostsvc.CapabilityResult{}, status.Error(codes.Unimplemented, "账户能力方法不受支持")
	}
}

func decodePasswordSecret(raw []byte) []byte {
	var decoded string
	if json.Unmarshal(raw, &decoded) == nil && decoded != "" {
		return []byte(decoded)
	}
	return append([]byte(nil), raw...)
}

func invalidAccountCall() (hostsvc.CapabilityResult, error) {
	return hostsvc.CapabilityResult{}, status.Error(codes.InvalidArgument, "账户能力请求类型无效")
}

func validationAccountFailure(message string) (hostsvc.CapabilityResult, error) {
	return hostsvc.CapabilityResult{Error: &hostsvc.DomainError{Code: "VALIDATION_FAILED", Message: message}}, nil
}
