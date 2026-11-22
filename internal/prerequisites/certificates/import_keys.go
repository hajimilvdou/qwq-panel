// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ImportAuthorizations 由宿主校验派发 operation 与其提取的导入私钥引用。
// 不能仅凭 ref 存在或 caller 传入的 purpose 允许读取。
type ImportAuthorizations interface {
	AllowImportKey(context.Context, Caller, secrets.Ref) error
}

type OwnedImportKeys struct {
	Secrets        *secrets.Store
	Authorizations ImportAuthorizations
}

func (r OwnedImportKeys) ReadImportKey(ctx context.Context, caller Caller, reference string) ([]byte, error) {
	if r.Secrets == nil || r.Authorizations == nil {
		return nil, fault.New("BACKEND_REQUIRED", "导入私钥需要宿主授权绑定")
	}
	if err := validateCaller(caller, true); err != nil {
		return nil, err
	}
	ref, err := secrets.ParseRef(reference)
	if err != nil {
		return nil, fault.New("VALIDATION_FAILED", "导入私钥引用无效")
	}
	if err := r.Authorizations.AllowImportKey(ctx, caller, ref); err != nil {
		return nil, backendFailure(err, "IMPORT_KEY_DENIED")
	}
	secret, err := r.Secrets.RevealOwned(ctx, ref, "plugins/tls.certificates", "plugin.operation")
	if err != nil {
		return nil, vaultFailure(err)
	}
	defer secret.Clear()
	raw := secret.Bytes()
	defer clear(raw)
	var text string
	if json.Unmarshal(raw, &text) != nil || text == "" || len(text) > tlsmgr.MaxPrivateKeyPEM {
		return nil, fault.New("PRIVATE_KEY_INVALID", "导入私钥秘密格式无效")
	}
	key := []byte(text)
	if !bytes.HasPrefix(bytes.TrimSpace(key), []byte("-----BEGIN ")) {
		clear(key)
		return nil, fault.New("PRIVATE_KEY_INVALID", "导入私钥不是 PEM")
	}
	if err := r.Authorizations.AllowImportKey(ctx, caller, ref); err != nil {
		clear(key)
		return nil, backendFailure(err, "IMPORT_KEY_DENIED")
	}
	return key, nil
}
