// SPDX-License-Identifier: AGPL-3.0-only

package testsupport

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/operations"
	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/platform/ids"
	"github.com/qwq-panel/qwq/internal/secrets"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 共享真实身份、权限与宿主 Operation 基础 ========================

// HostFixture 只装配基础宿主，不导入 hostauth 或提供业务授权替代品。
type HostFixture struct {
	Context    context.Context
	DB         *storage.DB
	Secrets    *secrets.Store
	Identity   *identity.Service
	Authorizer *authz.Authorizer
	Operations *operations.Service
	IDs        *ids.Generator
	Human      actor.Actor
}

// NewHost 复用真实 SQLite、AES-GCM、身份/权限与原 Operation 执行链。
func NewHost(t testing.TB, source clock.Clock, catalog operations.Catalog, dispatcher operations.Dispatcher) *HostFixture {
	t.Helper()
	host := &HostFixture{Context: context.Background(), IDs: ids.New(source.Now)}
	host.DB, host.Secrets = EncryptedStorage(t, source)
	var err error
	host.Identity, err = identity.New(identity.Options{DB: host.DB, Clock: source})
	if err != nil {
		t.Fatal(err)
	}
	host.Authorizer, err = authz.New(authz.Options{DB: host.DB, Clock: source, Principals: host.Identity})
	if err != nil {
		t.Fatal(err)
	}
	protector, err := secrets.NewOperationProtector(host.Context, host.Secrets)
	if err != nil {
		t.Fatal(err)
	}
	host.Operations, err = operations.New(operations.Options{DB: host.DB, Clock: source, IDs: host.IDs, NodeID: "local",
		Catalog: catalog, Dispatcher: dispatcher, Authorizer: hostRBAC{host.Authorizer}, Policy: hostPolicies{host.Authorizer},
		ArgumentProtector: protector, Config: operations.Config{JobWorkers: 4, JobQueue: 8, MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(host.Operations.Stop)
	if err := host.Operations.Start(host.Context); err != nil {
		t.Fatal(err)
	}
	return host
}

// User 创建并实际登录人类账号；每份 fixture 的首个用户使用 setup 成为管理员。
func (h *HostFixture) User(t testing.TB, name string, role authz.Role) actor.Actor {
	t.Helper()
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	defer clear(entropy[:])
	password := "Dnc7!" + base64.RawURLEncoding.EncodeToString(entropy[:])
	var login identity.LoginResult
	var err error
	if h.Human.ID == "" {
		token, _, err := h.Identity.NewSetupToken(h.Context)
		if err != nil {
			t.Fatal(err)
		}
		login, err = h.Identity.CompleteSetup(h.Context, identity.CompleteSetupInput{SetupToken: token, Username: name,
			DisplayName: name, Password: password, UserAgent: "DNC fixture"})
		if err != nil {
			t.Fatal(err)
		}
	} else {
		hash, err := h.Identity.PreparePassword(h.Context, name, password)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.DB.Update(h.Context, func(tx *storage.Tx) error {
			_, err := h.Identity.CreateUser(h.Context, tx, identity.CreateUserInput{Username: name, DisplayName: name,
				Role: identity.Role(role), PasswordHash: hash, Actor: h.Human})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		login, err = h.Identity.Login(h.Context, identity.LoginInput{Username: name, Password: password, UserAgent: "DNC fixture"})
		if err != nil {
			t.Fatal(err)
		}
	}
	who, session, err := h.Identity.AuthenticateSession(h.Context, login.Token)
	if err != nil || !who.IsHumanSession() || session.User.Role != identity.Role(role) {
		t.Fatalf("真实身份 fixture 无效：%v", err)
	}
	if h.Human.ID == "" {
		h.Human = who
	}
	return who
}

// Delegate 实际签发并认证委托，只返回当前 Actor，令牌不离开基础 fixture。
func (h *HostFixture) Delegate(t testing.TB, owner actor.Actor, policy authz.Policy) actor.Actor {
	t.Helper()
	var created authz.Created
	if err := h.DB.Update(h.Context, func(tx *storage.Tx) error {
		var err error
		created, err = h.Authorizer.CreateDelegation(h.Context, tx, authz.CreateDelegationInput{Actor: owner,
			Label: "DNC delegated fixture", Policy: policy})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	who, err := h.Authorizer.AuthenticateBearer(h.Context, created.Token)
	created.Token = ""
	if err != nil || who.Kind != actor.AIAgent || who.ID != created.Delegation.ID {
		t.Fatalf("真实委托 fixture 无效：%v", err)
	}
	return who
}

type hostRBAC struct{ backend *authz.Authorizer }

func (a hostRBAC) Authorize(ctx context.Context, who actor.Actor, action operations.Action, target operations.Target) error {
	permission, err := authz.ParsePermission(action.Permission)
	if err != nil {
		return err
	}
	node := target.NodeID
	if node == "" {
		node = "local"
	}
	return a.backend.Authorize(ctx, who, action.Permission, authz.Resource{Name: permission.Resource(), NodeID: node, Action: action.ID, Subject: target.Subject})
}

type hostPolicies struct{ backend *authz.Authorizer }

func (p hostPolicies) Limits(ctx context.Context, who actor.Actor, _ operations.Action, _ operations.Target) (operations.Limits, error) {
	limits := operations.Limits{AutoApproveMaxRisk: operations.RiskLow, OnApprovalRequired: operations.ApprovalQueue}
	if who.Kind == actor.AIAgent {
		delegation, err := p.backend.Delegation(ctx, who.ID)
		if err != nil {
			return operations.Limits{}, err
		}
		policy := delegation.Policy.Normalized()
		limits.AutoApproveMaxRisk, limits.OnApprovalRequired = policy.AutoApproveMaxRisk, policy.OnApprovalRequired
	}
	if mode, found := operations.PermissionModeFromContext(ctx); found {
		limits.PermissionMode = mode
	}
	return limits, nil
}
