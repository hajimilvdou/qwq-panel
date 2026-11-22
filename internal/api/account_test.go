// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// beginTOTP starts a TOTP enrollment over HTTP and returns the shared secret.
func (e *env) beginTOTP(a auth) []byte {
	e.t.Helper()
	var out struct {
		Secret     string `json:"secret"`
		OTPAuthURL string `json:"otpauth_url"`
		ExpiresAt  string `json:"expires_at"`
	}
	e.do(a.sign(http.MethodPost, "/api/v1/sessions/current/mfa/totp", "")).expect(e.t, http.StatusOK).decode(e.t, &out)
	if out.OTPAuthURL == "" || out.ExpiresAt == "" {
		e.t.Fatalf("enrollment = %+v", out)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(out.Secret)
	if err != nil {
		e.t.Fatalf("decode secret: %v", err)
	}
	return secret
}

// confirmTOTP posts the confirmation code of a pending enrollment.
func (e *env) confirmTOTP(a auth, code string) response {
	e.t.Helper()
	return e.do(a.sign(http.MethodPost, "/api/v1/sessions/current/mfa/totp/confirm", fmt.Sprintf(`{"code":%q}`, code)))
}

// TestTOTPEnrollFlow: begin → confirm turns the second factor on, the next login
// asks for it, and a recovery code works exactly once.
func TestTOTPEnrollFlow(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	secret := e.beginTOTP(a)
	var done struct {
		RecoveryCodes []string `json:"recovery_codes"`
		User          struct {
			MFAEnabled bool `json:"mfa_enabled"`
		} `json:"user"`
		Session struct {
			CSRFToken string `json:"csrf_token"`
		} `json:"session"`
	}
	e.confirmTOTP(a, totpAt(secret, 0)).expect(t, http.StatusOK).decode(t, &done)
	if len(done.RecoveryCodes) == 0 || !done.User.MFAEnabled || done.Session.CSRFToken == "" {
		t.Fatalf("confirm = %+v", done)
	}
	login := fmt.Sprintf(`{"username":%q,"password":%q}`, adminUser, adminPass)
	e.do(newRequest(http.MethodPost, "/api/v1/sessions", login)).expect(t, http.StatusOK)
	e.loginWithRecoveryCode(adminUser, done.RecoveryCodes[0])

	var challenge struct {
		ChallengeID string `json:"challenge_id"`
	}
	e.do(newRequest(http.MethodPost, "/api/v1/sessions", login)).expect(t, http.StatusOK).decode(t, &challenge)
	again := fmt.Sprintf(`{"challenge_id":%q,"method":"recovery_code","code":%q}`, challenge.ChallengeID, done.RecoveryCodes[0])
	e.do(newRequest(http.MethodPost, "/api/v1/sessions/mfa", again)).expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)

	// Turning it off needs a current code; a wrong one is 403, never 401.
	off := func(code string) response {
		return e.do(a.sign(http.MethodPost, "/api/v1/sessions/current/mfa/totp/disable", fmt.Sprintf(`{"code":%q}`, code)))
	}
	off(wrongTOTP(secret)).expectProblem(t, http.StatusForbidden, problem.MFARequired)
	if got := off(totpAt(secret, 1)).expect(t, http.StatusOK).decodeMap(t); got["mfa_enabled"] != false {
		t.Fatalf("after disable = %v", got)
	}
}

// TestDisableTOTPRouteMoved: the second factor is turned off with a POST; the
// old DELETE with a body is gone (it can no longer be routed).
func TestDisableTOTPRouteMoved(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	e.do(a.sign(http.MethodDelete, "/api/v1/sessions/current/mfa/totp", `{"code":"000000"}`)).
		expectProblem(t, http.StatusMethodNotAllowed, problem.MethodNotAllowed)
}

// updateProfile patches the caller's own display name.
func (e *env) updateProfile(a auth, body string, key int) response {
	e.t.Helper()
	req := a.sign(http.MethodPatch, "/api/v1/sessions/current/profile", body)
	if key > 0 {
		req.Header.Set("Idempotency-Key", idempotencyKey(key))
	}
	return e.do(req)
}

// ownRevision reads the revision of the signed-in user.
func (e *env) ownRevision(a auth) string {
	e.t.Helper()
	var cur struct {
		User struct {
			Revision string `json:"revision"`
		} `json:"user"`
	}
	e.do(a.sign(http.MethodGet, "/api/v1/sessions/current", "")).expect(e.t, http.StatusOK).decode(e.t, &cur)
	return cur.User.Revision
}

// TestUpdateProfile: every signed-in user, a viewer too, renames themself
// through host.account.update. The answer is the operation outcome carrying
// the user, a stale revision is 409, and the change is an operation of the
// caller that touched nobody else and published resource.changed.
func TestUpdateProfile(t *testing.T) {
	e := newEnv(t)
	e.setupAdmin(adminUser)
	v := e.signIn("vera", identity.RoleViewer)
	rev := e.ownRevision(v)

	e.updateProfile(v, fmt.Sprintf(`{"display_name":"Vera","expected_revision":%q}`, rev), 0).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	e.updateProfile(v, `{"display_name":"Vera"}`, 1).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	ctl := e.updateProfile(v, fmt.Sprintf(`{"display_name":"bad\u0007","expected_revision":%q}`, rev), 2).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	if len(ctl.Violations) != 1 || ctl.Violations[0].Pointer != "/display_name" {
		t.Fatalf("control character violations = %+v", ctl.Violations)
	}
	e.updateProfile(v, fmt.Sprintf(`{"display_name":"Vera","role":"admin","expected_revision":%q}`, rev), 3).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	var out struct {
		OperationID string `json:"operation_id"`
		Action      string `json:"action"`
		Status      string `json:"status"`
		Result      struct {
			UserID      string `json:"user_id"`
			DisplayName string `json:"display_name"`
			Role        string `json:"role"`
			Revision    string `json:"revision"`
		} `json:"result"`
	}
	body := fmt.Sprintf(`{"display_name":"Vera V.","expected_revision":%q}`, rev)
	e.updateProfile(v, body, 4).expect(t, http.StatusOK).decode(t, &out)
	if out.Action != "host.account.update" || out.Status != "SUCCEEDED" || out.OperationID == "" ||
		out.Result.UserID != v.userID || out.Result.DisplayName != "Vera V." || out.Result.Role != "viewer" ||
		out.Result.Revision == rev {
		t.Fatalf("outcome = %+v", out)
	}
	// The idempotent replay answers the same outcome.
	if got := e.updateProfile(v, body, 4).expect(t, http.StatusOK); got.header.Get("Idempotency-Replayed") != "true" {
		t.Fatalf("replay headers = %v", got.header)
	}
	// The old revision is stale now.
	e.updateProfile(v, fmt.Sprintf(`{"display_name":"Again","expected_revision":%q}`, rev), 5).
		expectProblem(t, http.StatusConflict, problem.RevisionConflict)

	var op struct {
		Actor struct {
			Kind string `json:"kind"`
			ID   string `json:"id"`
		} `json:"actor"`
		Target struct {
			Subject string `json:"subject"`
		} `json:"target"`
	}
	e.do(v.sign(http.MethodGet, "/api/v1/operations/"+out.OperationID, "")).expect(t, http.StatusOK).decode(t, &op)
	if op.Actor.ID != v.userID || op.Target.Subject != "users/"+v.userID {
		t.Fatalf("operation = %+v", op)
	}

	// Every open UI learns of the rename: one resource.changed of the caller's
	// user, tied to the operation, naming the member that changed.
	events, err := e.c.DB().EventsAfter(t.Context(), 0, 1000)
	if err != nil {
		t.Fatalf("EventsAfter: %v", err)
	}
	var changed []string
	for _, ev := range events {
		if ev.Type != "resource.changed" || ev.Subject != "users/"+v.userID || ev.OperationID != out.OperationID {
			continue
		}
		var p struct {
			Revision        string   `json:"revision"`
			ChangedPointers []string `json:"changed_pointers"`
		}
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("decode event payload: %v", err)
		}
		if p.Revision != out.Result.Revision {
			t.Fatalf("event revision = %q, user revision = %q", p.Revision, out.Result.Revision)
		}
		changed = append(changed, p.ChangedPointers...)
	}
	if len(changed) != 1 || changed[0] != "/display_name" {
		t.Fatalf("changed pointers = %v, want [/display_name]", changed)
	}
}

// TestProfileActionStaysOnCaller: host.account.update is reachable through a
// plan like every action, but only by a person and only for themself. Naming
// another user fails before that user's revision is compared with anything.
func TestProfileActionStaysOnCaller(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	v := e.signIn("vera", identity.RoleViewer)
	plan := func(who auth, target string) response {
		body := fmt.Sprintf(`{"action":"host.account.update","args":{"display_name":"Vera","expected_revision":%q}%s}`,
			e.ownRevision(who), target)
		return e.do(who.sign(http.MethodPost, "/api/v1/plans", body))
	}

	var own struct {
		RequiresApproval bool `json:"requires_approval"`
		Changes          []struct {
			Kind    string `json:"kind"`
			Subject string `json:"subject"`
		} `json:"changes"`
	}
	plan(v, "").expect(t, http.StatusCreated).decode(t, &own)
	if own.RequiresApproval || len(own.Changes) != 1 || own.Changes[0].Kind != "update" ||
		own.Changes[0].Subject != "users/"+v.userID {
		t.Fatalf("own plan = %+v", own)
	}
	plan(v, fmt.Sprintf(`,"target":{"subject":"users/%s"}`, v.userID)).expect(t, http.StatusCreated)

	other := fmt.Sprintf(`,"target":{"subject":"users/%s"},"expected_revision":%q`, a.userID, e.ownRevision(a))
	p := plan(v, other).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	if len(p.Violations) != 1 || p.Violations[0].Pointer != "/target/subject" || p.CurrentRevision != "" {
		t.Fatalf("foreign target = %+v", p)
	}

	// A service account has no account of its own and no way to the route.
	token := e.serviceToken(a)
	e.do(bearer(http.MethodPost, "/api/v1/plans",
		`{"action":"host.account.update","args":{"display_name":"CI","expected_revision":"1"}}`, token)).
		expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
	patch := bearer(http.MethodPatch, "/api/v1/sessions/current/profile", `{"display_name":"CI","expected_revision":"1"}`, token)
	patch.Header.Set("Idempotency-Key", idempotencyKey(9))
	e.do(patch).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
}

// TestReEnrollRequiresFreshMFA: with a second factor on, a stolen session that
// never passed it can neither start nor confirm a replacement secret.
func TestReEnrollRequiresFreshMFA(t *testing.T) {
	e := newEnv(t)
	stale := e.setupAdmin(adminUser)
	_, recovery := e.enableTOTP(stale.userID)
	e.do(stale.sign(http.MethodPost, "/api/v1/sessions/current/mfa/totp", "")).
		expectProblem(t, http.StatusForbidden, problem.MFARequired)

	fresh := e.loginWithRecoveryCode(adminUser, recovery[0])
	next := e.beginTOTP(fresh)
	e.confirmTOTP(stale, totpAt(next, 0)).expectProblem(t, http.StatusForbidden, problem.MFARequired)
	e.confirmTOTP(fresh, totpAt(next, 0)).expect(t, http.StatusOK)
}

// ======================== 公共兑换入口的失败节流 ========================
func TestEnrollmentTokenAttemptsAreThrottledOverHTTP(t *testing.T) {
	e := newEnv(t)
	e.setupAdmin(adminUser)
	body := `{"token":"not-a-valid-enrollment-token","password":"` + adminPass + `"}`
	for range identity.DefaultThrottleOptions().Threshold {
		e.do(newRequest(http.MethodPost, "/api/v1/enrollments", body)).expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)
	}
	response := e.do(newRequest(http.MethodPost, "/api/v1/enrollments", body))
	response.expectProblem(t, http.StatusTooManyRequests, problem.RateLimited)
	if response.header.Get("Retry-After") == "" {
		t.Fatal("enrollment backoff did not expose its retry time")
	}
}

// TestEnrollmentRedeemThenLogin 同时核验原有效 token 的密码策略和登录 cookie。
func TestEnrollmentRedeemThenLogin(t *testing.T) {
	e := newEnv(t)
	e.setupAdmin(adminUser)
	bob := e.insertUser("bob", identity.RoleOperator, "")
	var token string
	if err := e.c.DB().Update(t.Context(), func(tx *storage.Tx) error {
		var err error
		token, _, err = e.c.Identity().NewEnrollmentToken(t.Context(), tx, bob)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	redeem := func(password string) response {
		return e.do(newRequest(http.MethodPost, "/api/v1/enrollments", fmt.Sprintf(`{"token":%q,"password":%q}`, token, password)))
	}
	redeem("short").expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	s := e.sessionFrom(redeem(adminPass).expect(t, http.StatusCreated))
	if s.userID != bob {
		t.Fatalf("signed in as %s, want %s", s.userID, bob)
	}
	e.do(s.sign(http.MethodGet, "/api/v1/sessions/current", "")).expect(t, http.StatusOK)
	redeem(adminPass).expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)
	e.login("bob", adminPass)
}

// TestChangePasswordRevokesOtherSessions: a wrong current password is 403 (the
// session stays), success keeps this session and revokes every other one.
func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	other := e.login(adminUser, adminPass)
	const newPass = "an entirely new passphrase 42"
	change := func(current string) response {
		body := fmt.Sprintf(`{"current_password":%q,"new_password":%q}`, current, newPass)
		return e.do(a.sign(http.MethodPut, "/api/v1/sessions/current/password", body))
	}
	change("wrong password entirely").expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
	weak := e.do(a.sign(http.MethodPut, "/api/v1/sessions/current/password",
		fmt.Sprintf(`{"current_password":%q,"new_password":"short"}`, adminPass)))
	if p := weak.expectProblem(t, http.StatusBadRequest, problem.ValidationFailed); len(p.Violations) == 0 || p.Violations[0].Pointer != "/new_password" {
		t.Fatalf("violations = %+v", p.Violations)
	}
	change(adminPass).expect(t, http.StatusNoContent)
	e.do(a.sign(http.MethodGet, "/api/v1/sessions/current", "")).expect(t, http.StatusOK)
	e.do(other.sign(http.MethodGet, "/api/v1/sessions/current", "")).expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)
	old := fmt.Sprintf(`{"username":%q,"password":%q}`, adminUser, adminPass)
	e.do(newRequest(http.MethodPost, "/api/v1/sessions", old)).expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)
	e.login(adminUser, newPass)
}

// TestDestructiveApprovalWithMFA: end to end, a second factor enabled over HTTP
// lets the administrator approve a destructive user deletion.
func TestDestructiveApprovalWithMFA(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	secret := e.beginTOTP(a)
	e.confirmTOTP(a, totpAt(secret, 0)).expect(t, http.StatusOK)
	e.createApprovedUser(a, "bob", "viewer")
	bob := e.userByUsername(a, "bob")
	req := a.sign(http.MethodDelete, "/api/v1/users/"+mustString(t, bob, "user_id")+"?expected_revision="+mustString(t, bob, "revision"), "")
	req.Header.Set("Idempotency-Key", idempotencyKey(1))
	var op struct {
		ApprovalID string `json:"approval_id"`
	}
	e.do(req).expect(t, http.StatusAccepted).decode(t, &op)
	revision := mustString(t, e.approval(a, op.ApprovalID), "revision")
	e.decide(a, op.ApprovalID, "approve", revision, idempotencyKey(2)).expectProblem(t, http.StatusForbidden, problem.MFARequired)
	body := fmt.Sprintf(`{"decision":"approve","expected_revision":%q,"mfa_code":%q}`, revision, totpAt(secret, 1))
	approve := a.sign(http.MethodPost, "/api/v1/approvals/"+op.ApprovalID+"/decision", body)
	approve.Header.Set("Idempotency-Key", idempotencyKey(3))
	e.do(approve).expect(t, http.StatusOK)
}
