// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

const DefaultCapabilitySocket = "/run/qwq/capability.sock"

// CapabilityRequest 是独立能力 helper 的有界 envelope；不是任意命令原语。
// Secret 用 []byte 由 JSON 自动编码为 base64，仅 set-password 允许携带。
type CapabilityRequest struct {
	Op         string          `json:"op"`
	ID         string          `json:"id,omitempty"`
	ParamsJSON json.RawMessage `json:"params_json,omitempty"`
	Secret     []byte          `json:"secret_base64,omitempty"`
	Cursor     string          `json:"cursor,omitempty"`
}

// String 不展开秘密或业务参数。
func (CapabilityRequest) String() string   { return "sandbox.CapabilityRequest{[REDACTED]}" }
func (CapabilityRequest) GoString() string { return "sandbox.CapabilityRequest{[REDACTED]}" }

// Clear 清除本请求持有的可变缓冲；服务端解码后拥有这些缓冲。
func (r *CapabilityRequest) Clear() { clear(r.Secret); clear(r.ParamsJSON) }

// CapabilityResponse 区分传输与业务失败；Error 不得包含秘密或执行器输出。
type CapabilityResponse struct {
	OK         bool            `json:"ok"`
	Code       string          `json:"code,omitempty"`
	Error      string          `json:"error,omitempty"`
	ResultJSON json.RawMessage `json:"result_json,omitempty"`
	Version    string          `json:"version,omitempty"`
	UID        int             `json:"uid,omitempty"`
}

func (CapabilityResponse) String() string   { return "sandbox.CapabilityResponse{[REDACTED]}" }
func (CapabilityResponse) GoString() string { return "sandbox.CapabilityResponse{[REDACTED]}" }

// CapabilityRunner 只处理封闭 verb 集；具体能力实现决定程序/参数/受控路径。
type CapabilityRunner interface {
	Run(context.Context, CapabilityRequest) (CapabilityResponse, error)
}

// CapabilityClient 复用安装 helper 的连接、重试、deadline 与有界 JSON 传输。
// 每次独立连接，仅重试尚未连接成功的请求，已发送的写入永不自动重发。
type CapabilityClient struct{ *HelperClient }

func NewCapabilityClient(socket string) *CapabilityClient {
	return &CapabilityClient{HelperClient: NewHelperClient(socket)}
}

func (c *CapabilityClient) Call(ctx context.Context, request CapabilityRequest) (CapabilityResponse, error) {
	if err := ValidateCapabilityRequest(request); err != nil {
		return CapabilityResponse{}, problem.New(problem.ValidationFailed, "The capability request is invalid.")
	}
	// 拷贝并清除 wire 秘密，不修改调用方持有的缓冲。
	request.Secret = append([]byte(nil), request.Secret...)
	defer clear(request.Secret)
	var response CapabilityResponse
	if c == nil || c.HelperClient == nil {
		return response, problem.New(problem.Unavailable, "The capability helper is not configured.")
	}
	client := c.HelperClient
	if (request.Op == "docker.compose" || request.Op == "docker.recreate_ports") && client.Timeout == 0 {
		copied := *client
		copied.Timeout = 95 * time.Second
		client = &copied
	}
	if err := client.exchange(ctx, request, &response); err != nil {
		return response, err
	}
	if len(response.ResultJSON) > 0 && !json.Valid(response.ResultJSON) {
		return CapabilityResponse{}, problem.New(problem.Unavailable, "The capability helper returned an invalid result.")
	}
	return response, nil
}

// CapabilityVerbAllowed 对 helper 的全部动作实行精确白名单。
func CapabilityVerbAllowed(op string) bool {
	switch op {
	case "ping", "firewall.get", "firewall.apply", "firewall.reset", "firewall.detect", "firewall.restore", "firewall.sync-panel-port",
		"sshd.get-effective", "sshd.get-dropin", "sshd.write-dropin", "sshd.remove-dropin", "sshd.recover-dropin", "sshd.validate", "sshd.reload-socket", "sshd.verify-port",
		"account.list-keys", "account.import-key", "account.remove-key", "account.generate-key", "account.set-password",
		"ban.scan", "ban.apply", "ban.remove", "ban.list",
		"traffic.status", "traffic.apply", "traffic.clear",
		"sysctl.apply", "sysctl.rollback",
		"docker.api.read", "docker.api.write", "docker.compose",
		"docker.bindable_ips", "docker.network.create", "docker.network.membership", "docker.recreate_ports":
		return true
	default:
		return false
	}
}

// ValidateCapabilityRequest 在连接或执行前拒绝非法 verb、身份、参数和秘密用途。
func ValidateCapabilityRequest(request CapabilityRequest) error {
	if !CapabilityVerbAllowed(request.Op) {
		return errors.New("sandbox: capability verb is not allowed")
	}
	if request.Op != "ping" {
		if err := ValidateID(request.ID); err != nil {
			return errors.New("sandbox: invalid capability caller")
		}
	}
	if len(request.ParamsJSON) > MaxHelperMessage || len(request.Cursor) > 512 {
		return errors.New("sandbox: capability parameters exceed limits")
	}
	if len(request.ParamsJSON) > 0 {
		if err := validateHelperDocument(request.ParamsJSON); err != nil {
			return errors.New("sandbox: invalid capability parameters")
		}
	}
	if len(request.Secret) > 8192 || (len(request.Secret) > 0 && request.Op != "account.set-password") {
		return errors.New("sandbox: secret is not allowed for this verb")
	}
	return nil
}
