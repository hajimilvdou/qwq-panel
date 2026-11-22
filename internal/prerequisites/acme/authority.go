// SPDX-License-Identifier: AGPL-3.0-only

package acme

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"slices"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
	xacme "golang.org/x/crypto/acme"
)

// ======================== 原订单与固定 CSR 的实际签发 ========================

func (a *Authority) Issue(ctx context.Context, caller certificates.Caller, certificateID, attemptID string, scope certificates.IssuanceScope, progress certificates.Progress) (certificates.Issued, error) {
	return a.run(ctx, caller, certificateID, attemptID, scope, progress)
}
func (a *Authority) Reconcile(ctx context.Context, caller certificates.Caller, certificateID, attemptID string, scope certificates.IssuanceScope, progress certificates.Progress) (certificates.Issued, error) {
	return a.run(ctx, caller, certificateID, attemptID, scope, progress)
}

func (a *Authority) run(ctx context.Context, caller certificates.Caller, certificateID, attemptID string, input certificates.IssuanceScope, progress certificates.Progress) (issued certificates.Issued, err error) {
	if !names.ID(caller.OwnerID) || !names.ID(caller.OperationID) || !names.ID(certificateID) || !names.ID(attemptID) {
		return issued, fault.New("PERMISSION_DENIED", "ACME 调用身份无效")
	}
	scope, err := canonicalScope(input)
	if err != nil {
		return issued, err
	}
	if err := a.authorize(ctx, caller, certificateID, scope); err != nil {
		return issued, err
	}
	bounded, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	ctx = bounded
	state, revision, found, err := a.load(ctx, caller, certificateID, attemptID, scope)
	if err != nil {
		return issued, err
	}
	if !found {
		// 原订单 API 只能在日志保存后发送；无日志意味着该原 attempt 尚未发订单。
		state, revision, err = a.prepare(ctx, caller, certificateID, attemptID, scope)
		if err != nil {
			return issued, err
		}
	}
	if state.Phase == "rejected" {
		return issued, &fault.Error{Code: state.ErrorCode, Detail: "原 CA 订单已明确拒绝", RetryAt: state.RetryAt, NotApplied: true}
	}
	state, revision, err = a.lease(ctx, caller, state, revision)
	if err != nil {
		return issued, err
	}
	defer func() {
		if releaseErr := a.release(ctx, caller, state); releaseErr != nil {
			err = errors.Join(err, releaseErr)
		}
	}()
	if existing, findErr := a.vault.Find(ctx, caller, certificateID, attemptID); findErr == nil {
		return existing, nil
	} else if fault.Code(findErr) != "NOT_FOUND" {
		return issued, findErr
	}
	owner, err := keyOwner(caller, certificateID)
	if err != nil {
		return issued, err
	}
	certKey, err := a.readKey(ctx, owner, keyPurpose(attemptID), state.KeyRef)
	if err != nil {
		return issued, err
	}
	defer clearSigner(certKey)
	csr, err := x509.ParseCertificateRequest(state.CSR)
	if err != nil || !samePublicKey(csr.PublicKey, certKey.Public()) {
		return issued, fault.New("STATE_INVALID", "原 CSR 与保存的证书私钥不符")
	}
	_, accountKey, err := a.ensureKey(ctx, accountOwner(caller, scope.CA), "acme.account")
	if err != nil {
		return issued, err
	}
	defer clearSigner(accountKey)
	client, guard, err := a.acmeClient(caller, certificateID, scope, accountKey, state.AccountURI)
	if err != nil {
		return issued, err
	}
	if state.AccountURI == "" {
		account, accountErr := client.GetReg(ctx, "")
		if errors.Is(accountErr, xacme.ErrNoAccount) {
			account, accountErr = client.Register(ctx, &xacme.Account{}, func(value string) bool {
				parsed, err := url.Parse(value)
				return err == nil && parsed.Scheme == "https" && parsed.Host == "letsencrypt.org" && a.terms.Accept(ctx, caller, scope.CA, value) == nil
			})
		}
		if accountErr != nil {
			return issued, guard.failure(accountErr, false)
		}
		if account == nil || account.Status != xacme.StatusValid || !allowedURL(scope.CA, account.URI) {
			return issued, fault.New("CA_UNAVAILABLE", "CA 账户响应不属于受控有效账户")
		}
		state.AccountURI = account.URI
		revision, err = a.saveDetached(ctx, caller, state, revision)
		if err != nil {
			return issued, err
		}
		client.KID = xacme.KeyID(account.URI)
	}
	if err := a.caa.CheckCAA(ctx, scope.Provider, scope.Spec.SANs, state.AccountURI); err != nil {
		return issued, err
	}
	if err := report(progress, "issuing", 25); err != nil {
		return issued, err
	}
	var order *xacme.Order
	if state.OrderURI == "" {
		if state.Phase != "prepared" {
			return issued, outcome("原订单响应未保存，不能创建替代订单")
		}
		state.Phase = "submitting_order"
		revision, err = a.save(ctx, caller, state, revision)
		if err != nil {
			return issued, err
		}
		identifiers := make([]xacme.AuthzID, 0, len(scope.Spec.SANs))
		for _, san := range scope.Spec.SANs {
			identifiers = append(identifiers, xacme.AuthzID{Type: "dns", Value: san})
		}
		order, err = client.AuthorizeOrder(ctx, identifiers)
		if err != nil {
			failure := guard.failure(err, true)
			var rejected *fault.Error
			if errors.As(failure, &rejected) && rejected.NotApplied {
				state.Phase, state.ErrorCode, state.RetryAt = "rejected", rejected.Code, rejected.RetryAt
				_, saveErr := a.saveDetached(ctx, caller, state, revision)
				if saveErr != nil {
					return issued, errors.Join(failure, saveErr)
				}
			}
			return issued, failure
		}
		if err := validateOrder(scope, order); err != nil {
			return issued, outcome("CA 新订单结果不能匹配原 SAN 或端点")
		}
		state.OrderURI, state.FinalizeURI, state.Phase = order.URI, order.FinalizeURL, "order_created"
		revision, err = a.saveDetached(ctx, caller, state, revision)
		if err != nil {
			return issued, outcome("CA 订单已创建但地址未持久化")
		}
	} else {
		order, err = client.GetOrder(ctx, state.OrderURI)
		if err != nil {
			return issued, guard.failure(err, false)
		}
		if err := validateOrder(scope, order); err != nil || order.URI != state.OrderURI || order.FinalizeURL != state.FinalizeURI {
			return issued, fault.New("STATE_INVALID", "CA 原订单范围或 finalize 地址变化")
		}
	}
	if order.Status == xacme.StatusInvalid {
		return issued, a.rejectOrder(ctx, caller, &state, revision)
	}
	if order.Status == xacme.StatusPending {
		if err := a.authorizations(ctx, caller, &state, &revision, client, guard, order, progress); err != nil {
			return issued, err
		}
		order, err = client.WaitOrder(ctx, state.OrderURI)
		if err != nil {
			return issued, guard.failure(err, false)
		}
		if err := validateOrder(scope, order); err != nil {
			return issued, err
		}
	}
	if err := report(progress, "issuing", 75); err != nil {
		return issued, err
	}
	var chain [][]byte
	var certURL string
	switch order.Status {
	case xacme.StatusReady:
		if state.Phase == "finalizing" {
			return issued, outcome("原 finalize 已发送但结果未确认，只允许读取原订单")
		}
		if err := a.caa.CheckCAA(ctx, scope.Provider, scope.Spec.SANs, state.AccountURI); err != nil {
			return issued, err
		}
		state.Phase = "finalizing"
		revision, err = a.save(ctx, caller, state, revision)
		if err != nil {
			return issued, err
		}
		chain, certURL, err = client.CreateCertFromOrder(ctx, order, state.CSR, true)
		if err != nil {
			return issued, postOrderFailure(guard.failure(err, true))
		}
	case xacme.StatusProcessing:
		order, err = client.WaitOrder(ctx, state.OrderURI)
		if err != nil {
			return issued, guard.failure(err, false)
		}
		if validateOrder(scope, order) != nil || order.Status != xacme.StatusValid {
			return issued, outcome("原订单签发终态未确认")
		}
		fallthrough
	case xacme.StatusValid:
		certURL = order.CertURL
		if !allowedURL(scope.CA, certURL) {
			return issued, fault.New("STATE_INVALID", "原证书下载端点无效")
		}
		chain, err = client.FetchCert(ctx, certURL, true)
		if err != nil {
			return issued, guard.failure(err, false)
		}
	case xacme.StatusInvalid:
		return issued, a.rejectOrder(ctx, caller, &state, revision)
	default:
		return issued, outcome("原订单尚不能确认签发状态")
	}
	if !allowedURL(scope.CA, certURL) || len(chain) == 0 || len(chain) > 16 {
		return issued, fault.New("CERTIFICATE_CHAIN_INVALID", "CA 证书链或下载地址无效")
	}
	state.CertificateURI = certURL
	revision, err = a.saveDetached(ctx, caller, state, revision)
	if err != nil {
		return issued, err
	}
	certificatePEM := []byte{}
	for _, der := range chain {
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	privatePEM, err := keyPEM(certKey)
	if err != nil {
		return issued, err
	}
	defer clear(privatePEM)
	material, err := tlsmgr.NewMaterial(certificatePEM, privatePEM)
	if err != nil {
		return issued, err
	}
	defer material.Clear()
	trust := tlsmgr.PublicTrust
	if scope.CA == certificates.LetsEncryptStaging {
		trust = tlsmgr.StagingTrust
	}
	reference, err := a.vault.EnsureMaterial(ctx, caller, certificateID, attemptID, material, scope.Spec, trust)
	if err != nil {
		return issued, err
	}
	state.Material, state.Phase = reference, "issued"
	_, err = a.saveDetached(ctx, caller, state, revision)
	return certificates.Issued{Material: reference, Trust: trust}, err
}

func validateOrder(scope certificates.IssuanceScope, order *xacme.Order) error {
	if order == nil || !allowedURL(scope.CA, order.URI) || !allowedURL(scope.CA, order.FinalizeURL) || len(order.Identifiers) != len(scope.Spec.SANs) || len(order.AuthzURLs) > 16 {
		return fault.New("CA_UNAVAILABLE", "CA 订单形状无效")
	}
	identifiers := []string{}
	for _, identifier := range order.Identifiers {
		if identifier.Type != "dns" {
			return fault.New("CA_UNAVAILABLE", "CA 返回了非 DNS 标识")
		}
		identifiers = append(identifiers, identifier.Value)
	}
	slices.Sort(identifiers)
	if !slices.Equal(identifiers, scope.Spec.SANs) {
		return fault.New("SAN_MISMATCH", "CA 订单 SAN 与原授权不符")
	}
	for _, value := range order.AuthzURLs {
		if !allowedURL(scope.CA, value) {
			return fault.New("CA_UNAVAILABLE", "CA 授权端点不属于受控 CA")
		}
	}
	return nil
}

func (a *Authority) rejectOrder(ctx context.Context, caller certificates.Caller, state *journal, revision string) error {
	state.Phase, state.ErrorCode = "rejected", "CA_REJECTED"
	if _, err := a.saveDetached(ctx, caller, *state, revision); err != nil {
		return err
	}
	return &fault.Error{Code: "CA_REJECTED", Detail: "CA 原订单已进入不可签发终态", NotApplied: true}
}

func report(progress certificates.Progress, stage string, percent uint32) error {
	if progress == nil {
		return nil
	}
	return progress(stage, percent)
}
func outcome(detail string) error {
	return &fault.Error{Code: "OUTCOME_UNKNOWN", Detail: detail, Uncertain: true}
}
func postOrderFailure(err error) error {
	var failure *fault.Error
	if errors.As(err, &failure) {
		copy := *failure
		copy.NotApplied, copy.Uncertain = false, true
		return &copy
	}
	return outcome("原订单已存在，签发结果未确认")
}
func samePublicKey(a, b any) bool {
	left, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	right, err := x509.MarshalPKIXPublicKey(b)
	return err == nil && slices.Equal(left, right)
}

var _ certificates.Authority = (*Authority)(nil)
