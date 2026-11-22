// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"strings"

	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
)

// ======================== 宿主账号创建契约；范围始终来自私有策略 ========================

const RenewalBootstrapAction = "host.service_accounts.renewal_bootstrap"

type RenewalBootstrapArgs struct {
	PolicyID         string `json:"policy_id"`
	ExpectedRevision string `json:"expected_revision"`
}

func (a RenewalBootstrapArgs) Validate() error {
	if !names.ID(a.PolicyID) {
		return problem.Validation(problem.Violation{Pointer: "/policy_id", Code: "INVALID", Message: "续期策略 ID 无效。"})
	}
	if len(a.ExpectedRevision) == 0 || len(a.ExpectedRevision) > 64 || strings.ContainsFunc(a.ExpectedRevision, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._~-", r))
	}) {
		return problem.Validation(problem.Violation{Pointer: "/expected_revision", Code: "INVALID", Message: "必须提供当前续期策略版本。"})
	}
	return nil
}

func (a RenewalBootstrapArgs) Subject() string {
	return "plugins/tls.certificates/resources/policies/" + a.PolicyID
}

// RenewalBootstrapResult 永不包含一次性 bearer、完整私有策略或证书材料。
type RenewalBootstrapResult struct {
	ServiceAccountID string `json:"service_account_id"`
}
