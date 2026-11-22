// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 只在当次事务内可用的创建器 ========================

type renewalBootstrapKey struct{}

type renewalBootstrapExecution struct {
	source   *renewalServiceSource
	tx       *storage.Tx
	who      actor.Actor
	prepared hostauth.RenewalServiceRequest
	holder   *renewalPolicyHolder
	lifetime context.Context
}

func (*renewalBootstrapExecution) String() string {
	return "controller.renewalBootstrapExecution{[REDACTED]}"
}
func (*renewalBootstrapExecution) GoString() string {
	return "controller.renewalBootstrapExecution{[REDACTED]}"
}

type renewalServiceSource struct {
	controller *Controller
	nodeID     string
}

func (s *renewalServiceSource) canonicalRequest(input hostauth.RenewalServiceRequest) (hostauth.RenewalServiceRequest, error) {
	if s == nil || s.controller == nil || s.controller.closed.Load() || !names.ID(input.PolicyID) || !s.controller.clk.Now().Before(input.ExpiresAt) {
		return hostauth.RenewalServiceRequest{}, problem.New(problem.PermissionDenied, "续期授权已经到期或后端不可用。")
	}
	scope, err := certificates.CanonicalRenewalScope(input.Scope)
	if err != nil || scope.OwnerID != "tls.certificates" || len(scope.Consumers) == 0 {
		return hostauth.RenewalServiceRequest{}, problem.New(problem.PermissionDenied, "续期账号需要已确认的完整私有范围。")
	}
	for _, consumer := range scope.Consumers {
		if consumer.NodeID != s.nodeID {
			return hostauth.RenewalServiceRequest{}, problem.New(problem.PermissionDenied, "续期消费者超出当前实际节点。")
		}
	}
	input.Scope, input.ExpiresAt = scope, input.ExpiresAt.UTC()
	return input, nil
}

func (s *renewalServiceSource) serviceScope(request hostauth.RenewalServiceRequest) *authz.ServiceScope {
	return &authz.ServiceScope{Actions: []string{"tls.certificates/renew_existing"}, NodeIDs: []string{s.nodeID},
		Subjects: []string{"plugins/tls.certificates/resources/certificates/" + request.Scope.CertificateID}, ExpiresAt: request.ExpiresAt}
}

func (s *renewalServiceSource) requestDigest(request hostauth.RenewalServiceRequest, creatorID string) ([32]byte, error) {
	raw, err := json.Marshal(struct {
		NodeID    string                         `json:"node_id"`
		CreatorID string                         `json:"creator_id"`
		Request   hostauth.RenewalServiceRequest `json:"request"`
	}{s.nodeID, creatorID, request})
	defer clear(raw)
	return sha256.Sum256(raw), err
}

func (s *renewalServiceSource) EnsureRenewalService(ctx context.Context, who actor.Actor, input hostauth.RenewalServiceRequest) (string, error) {
	if s == nil || s.controller == nil || ctx == nil {
		return "", problem.New(problem.ApprovalRequired, "续期账号创建缺少当前同步宿主事务。")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	proof, ok := ctx.Value(renewalBootstrapKey{}).(*renewalBootstrapExecution)
	if !ok || proof == nil || proof.source != s || proof.tx == nil || proof.who != who ||
		proof.holder == nil || s.controller.renewalPolicies.Load() != proof.holder || proof.lifetime == nil || proof.lifetime.Err() != nil {
		return "", problem.New(problem.ApprovalRequired, "续期账号必须由当次真实宿主交互入口创建。")
	}
	prepared, err := s.canonicalRequest(input)
	if err != nil {
		return "", err
	}
	expected, err := s.requestDigest(proof.prepared, who.ID)
	if err != nil {
		return "", err
	}
	actual, err := s.requestDigest(prepared, who.ID)
	if err != nil || actual != expected {
		return "", problem.New(problem.PermissionDenied, "续期账号请求超出当次私有确认范围。")
	}
	c := s.controller
	verified, err := c.id.VerifyHumanSessionTx(ctx, proof.tx, who)
	if err != nil {
		return "", err
	}
	if err := c.auth.AuthorizeHumanTx(ctx, proof.tx, verified, "host.service_accounts:create"); err != nil {
		return "", err
	}
	name := "renewal." + hex.EncodeToString(actual[:28])
	existing, err := c.auth.ServiceAccountByNameTx(ctx, proof.tx, name)
	if err == nil {
		if err := s.validateExisting(ctx, proof.tx, existing, prepared, verified.ID); err != nil {
			return "", err
		}
		return existing.ID, nil
	}
	if !problem.HasCode(err, problem.NotFound) {
		return "", err
	}
	created, err := c.auth.CreateServiceAccount(ctx, proof.tx, authz.CreateServiceAccountInput{
		Actor: verified, Name: name, Role: authz.RoleOperator, Scope: s.serviceScope(prepared)})
	if err != nil {
		return "", err
	}
	// 不把一次性token送回调用方；运行主体由私有policy登记真实service ID。
	created.Token = ""
	return created.ID, nil
}

func (s *renewalServiceSource) validateExisting(ctx context.Context, tx *storage.Tx, account authz.ServiceAccount, request hostauth.RenewalServiceRequest, creatorID string) error {
	want := s.serviceScope(request)
	if account.Disabled || account.CreatedBy != creatorID || account.Role != authz.RoleOperator || account.Scope == nil || account.Scope.Validate() != nil ||
		!account.Scope.ExpiresAt.Equal(want.ExpiresAt) || !slices.Equal(account.Scope.Actions, want.Actions) ||
		!slices.Equal(account.Scope.NodeIDs, want.NodeIDs) || !slices.Equal(account.Scope.Subjects, want.Subjects) {
		return problem.New(problem.StateConflict, "同名续期账号的创建者、状态或精确权限与私有策略不符。")
	}
	creator := actor.Actor{Kind: actor.Human, ID: account.CreatedBy}
	return s.controller.auth.AuthorizeHumanTx(ctx, tx, creator, "system.certificates:manage")
}
