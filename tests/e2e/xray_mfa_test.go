// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e && linux

package e2e

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/identity"
)

// xrayMFA 只标记本轮管理员已完成 TOTP 注册；材料在注册返回时清零。
type xrayMFA struct{}

func enrollXrayMFA(p *panel) *xrayMFA {
	p.t.Helper()
	var enrollment struct {
		Secret string `json:"secret"`
	}
	decodeXraySensitive(p, p.request(http.MethodPost, "/api/v1/sessions/current/mfa/totp", nil, "", false), http.StatusOK, &enrollment)
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(strings.ToUpper(enrollment.Secret), "="))
	defer clear(secret)
	if err != nil || len(secret) < 16 {
		p.t.Fatal("测试管理员 TOTP 申请无效")
	}
	enrollment.Secret = ""
	step := identity.TOTPStep(time.Now())
	code := identity.TOTPCode(secret, step)
	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		p.t.Fatal(err)
	}
	defer clear(body)
	decodeXraySensitive(p, p.request(http.MethodPost, "/api/v1/sessions/current/mfa/totp/confirm", bytes.NewReader(body), "application/json", false), http.StatusOK, nil)
	return &xrayMFA{}
}

func decodeXraySensitive(p *panel, response *http.Response, expected int, output any) {
	p.t.Helper()
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (32<<10)+1))
	defer clear(data)
	if err != nil || len(data) > 32<<10 || response.StatusCode != expected {
		p.t.Fatalf("敏感夹具接口 %s 返回 %d，期望 %d", response.Request.URL.Path, response.StatusCode, expected)
	}
	if output != nil && json.Unmarshal(data, output) != nil {
		p.t.Fatal("敏感夹具接口响应格式无效")
	}
}

// requireXrayApproval 验证 high/write 等待真人批准；ADR-0004 的 MFA 下限属于 destructive。
func requireXrayApproval(p *panel, operation *operationResult) {
	p.t.Helper()
	if operation.Status != "AWAITING_APPROVAL" {
		p.t.Fatal("高敏 Apply 没有等待人类审批")
	}
	var approval struct {
		Revision    string `json:"revision"`
		RequiresMFA bool   `json:"requires_mfa"`
	}
	p.decode(p.request(http.MethodGet, "/api/v1/approvals/"+operation.ApprovalID, nil, "", false), http.StatusOK, &approval)
	if approval.Revision == "" || approval.RequiresMFA {
		p.t.Fatal("write 审批的第二因素字段不符合 ADR-0004")
	}
}
