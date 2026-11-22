// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/secrets"
)

// ======================== 原导入 operation 的单个私钥引用 ========================

func (a *Authority) AllowImportKey(ctx context.Context, caller certificates.Caller, ref secrets.Ref) error {
	grant, err := a.certificateGrant(ctx, caller)
	if err != nil {
		return err
	}
	if grant.access != certificates.Import || !ref.Valid() || ref != grant.keyRef {
		return fault.New("PERMISSION_DENIED", "私钥引用不属于原已接受证书导入")
	}
	return nil
}

// ReadImportKey 复用 OwnedImportKeys 的 owner/purpose 校验、真实秘密读取与清零。
func (a *Authority) ReadImportKey(ctx context.Context, caller certificates.Caller, reference string) ([]byte, error) {
	if a == nil {
		return nil, fault.New("BACKEND_REQUIRED", "导入私钥需要真实宿主权限后端")
	}
	return (certificates.OwnedImportKeys{Secrets: a.secrets, Authorizations: a}).ReadImportKey(ctx, caller, reference)
}

var _ certificates.ImportAuthorizations = (*Authority)(nil)
var _ certificates.ImportKeyReader = (*Authority)(nil)
