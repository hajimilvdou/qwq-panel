// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/api"
	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// TestUsersAndApprovals walks the single write path for a user: an operation is
// queued for approval, decided, executed, then updated and deleted through the
// same route. It also covers the documented error paths of the routes.
func TestUsersAndApprovals(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)

	// Unauthenticated access is refused before any handler runs.
	e.do(newRequest(http.MethodGet, "/api/v1/users", "")).
		expectProblem(t, http.StatusUnauthorized, problem.Unauthenticated)

	list := e.do(a.sign(http.MethodGet, "/api/v1/users", "")).expect(t, http.StatusOK)
	var page struct {
		Items      []map[string]any `json:"items"`
		NextCursor string           `json:"next_cursor"`
		Revision   string           `json:"revision"`
		Delta      bool             `json:"delta"`
	}
	list.decode(t, &page)
	if len(page.Items) != 1 || mustString(t, page.Items[0], "username") != adminUser {
		t.Fatalf("initial users = %v", page.Items)
	}
	if page.Revision == "" {
		t.Fatal("list has no revision watermark")
	}
	if page.Delta {
		t.Fatal("a full snapshot must have delta=false")
	}
	if mustString(t, page.Items[0], "role") != "admin" {
		t.Fatalf("admin role = %v", page.Items[0]["role"])
	}

	// fields projects each item; identifiers and the revision are kept.
	projected := e.do(a.sign(http.MethodGet, "/api/v1/users?fields=/username", "")).expect(t, http.StatusOK)
	var projPage struct {
		Items []map[string]any `json:"items"`
	}
	projected.decode(t, &projPage)
	if len(projPage.Items) != 1 {
		t.Fatalf("projected items = %v", projPage.Items)
	}
	item := projPage.Items[0]
	if _, ok := item["role"]; ok {
		t.Fatalf("role was not projected away: %v", item)
	}
	for _, key := range []string{"username", "user_id", "revision"} {
		if _, ok := item[key]; !ok {
			t.Fatalf("projection dropped %q: %v", key, item)
		}
	}
	// An unknown pointer is a validation problem at /fields.
	e.do(a.sign(http.MethodGet, "/api/v1/users?fields=/nope", "")).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	// Mutating routes require an Idempotency-Key.
	noKey := e.do(a.sign(http.MethodPost, "/api/v1/users", `{"username":"bob","role":"operator"}`)).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	if len(noKey.Violations) == 0 || noKey.Violations[0].Pointer != "/Idempotency-Key" {
		t.Fatalf("violations = %+v", noKey.Violations)
	}

	// Unknown members are rejected, never ignored.
	unknown := a.sign(http.MethodPost, "/api/v1/users", `{"username":"bob","role":"operator","extra":1}`)
	unknown.Header.Set("Idempotency-Key", idempotencyKey(9))
	bad := e.do(unknown).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	if len(bad.Violations) == 0 || bad.Violations[0].Pointer != "/extra" || bad.Violations[0].Code != "UNKNOWN_FIELD" {
		t.Fatalf("violations = %+v", bad.Violations)
	}

	// The args schema of the host action is validated before an operation is
	// queued, so a typo is a 400 instead of an operation that can only fail.
	badRole := a.sign(http.MethodPost, "/api/v1/users", `{"username":"eve","role":"root"}`)
	badRole.Header.Set("Idempotency-Key", idempotencyKey(11))
	e.do(badRole).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	badName := a.sign(http.MethodPost, "/api/v1/users", `{"username":"Eve Smith","role":"viewer"}`)
	badName.Header.Set("Idempotency-Key", idempotencyKey(12))
	e.do(badName).expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)

	// Creating a user is risk high: 202 with an operation awaiting approval.
	key := idempotencyKey(1)
	approvalID, operationID := e.createUser(a, "bob", "operator", key)

	// The same key with the same request replays the stored response.
	replay := a.sign(http.MethodPost, "/api/v1/users", `{"username":"bob","role":"operator"}`)
	replay.Header.Set("Idempotency-Key", key)
	replayed := e.do(replay).expect(t, http.StatusAccepted)
	if replayed.header.Get("Idempotency-Replayed") != "true" {
		t.Fatal("replay did not set Idempotency-Replayed")
	}
	var replayOp struct {
		OperationID string `json:"operation_id"`
	}
	replayed.decode(t, &replayOp)
	if replayOp.OperationID != operationID {
		t.Fatalf("replayed operation = %q, want %q", replayOp.OperationID, operationID)
	}

	// The same key with a different request is a conflict.
	changed := a.sign(http.MethodPost, "/api/v1/users", `{"username":"carol","role":"viewer"}`)
	changed.Header.Set("Idempotency-Key", key)
	e.do(changed).expectProblem(t, http.StatusUnprocessableEntity, problem.IdempotencyKeyReused)

	// The approval carries the facts of the operation.
	approval := e.approval(a, approvalID)
	if mustString(t, approval, "status") != "PENDING" {
		t.Fatalf("approval status = %v", approval["status"])
	}
	facts, _ := approval["facts"].(map[string]any)
	action, _ := facts["action"].(map[string]any)
	if mustString(t, action, "id") != "host.users.create" {
		t.Fatalf("facts.action = %v", action)
	}
	if mustString(t, facts, "effective_risk") != "high" {
		t.Fatalf("effective_risk = %v", facts["effective_risk"])
	}
	if approval["requires_mfa"] != false {
		t.Fatalf("requires_mfa = %v", approval["requires_mfa"])
	}
	revision := mustString(t, approval, "revision")

	// A stale expected_revision is REVISION_CONFLICT with the current one.
	conflict := e.decide(a, approvalID, "approve", "999999", idempotencyKey(2)).
		expectProblem(t, http.StatusConflict, problem.RevisionConflict)
	if conflict.CurrentRevision != revision {
		t.Fatalf("current_revision = %q, want %q", conflict.CurrentRevision, revision)
	}

	// Approving runs the host action synchronously.
	decided := e.decide(a, approvalID, "approve", revision, idempotencyKey(3)).expect(t, http.StatusOK)
	var decidedBody map[string]any
	decided.decode(t, &decidedBody)
	if mustString(t, decidedBody, "status") != "APPROVED" {
		t.Fatalf("decided approval = %s", decided.body)
	}

	bob := e.userByUsername(a, "bob")
	if mustString(t, bob, "role") != "operator" {
		t.Fatalf("bob = %v", bob)
	}

	// Pagination: limit=1 returns a cursor for the second user.
	first := e.do(a.sign(http.MethodGet, "/api/v1/users?limit=1", "")).expect(t, http.StatusOK)
	var firstPage struct {
		Items      []map[string]any `json:"items"`
		NextCursor string           `json:"next_cursor"`
	}
	first.decode(t, &firstPage)
	if len(firstPage.Items) != 1 || firstPage.NextCursor == "" {
		t.Fatalf("first page = %+v", firstPage)
	}
	second := e.do(a.sign(http.MethodGet, "/api/v1/users?limit=1&cursor="+firstPage.NextCursor, "")).expect(t, http.StatusOK)
	var secondPage struct {
		Items      []map[string]any `json:"items"`
		NextCursor string           `json:"next_cursor"`
	}
	second.decode(t, &secondPage)
	if len(secondPage.Items) != 1 || secondPage.NextCursor != "" {
		t.Fatalf("second page = %+v", secondPage)
	}
	if mustString(t, secondPage.Items[0], "user_id") == mustString(t, firstPage.Items[0], "user_id") {
		t.Fatal("the second page repeated the first user")
	}

	// get one user, and a missing one.
	if got := e.do(a.sign(http.MethodGet, "/api/v1/users/"+mustString(t, bob, "user_id"), "")).expect(t, http.StatusOK); len(got.body) == 0 {
		t.Fatal("empty user body")
	}
	e.do(a.sign(http.MethodGet, "/api/v1/users/usr_does_not_exist", "")).
		expectProblem(t, http.StatusNotFound, problem.NotFound)

	// Update: 202, approve, then the display name changed.
	bobID := mustString(t, bob, "user_id")
	bobRevision := mustString(t, bob, "revision")
	patch := fmt.Sprintf(`{"expected_revision":%q,"display_name":"Bob"}`, bobRevision)
	updateReq := a.sign(http.MethodPatch, "/api/v1/users/"+bobID, patch)
	updateReq.Header.Set("Idempotency-Key", idempotencyKey(4))
	updated := e.do(updateReq).expect(t, http.StatusAccepted)
	var updateOp struct {
		ApprovalID string `json:"approval_id"`
	}
	updated.decode(t, &updateOp)
	updateApproval := e.approval(a, updateOp.ApprovalID)
	if mustString(t, updateApproval, "status") != "PENDING" {
		t.Fatalf("update approval = %v", updateApproval["status"])
	}
	e.decide(a, updateOp.ApprovalID, "approve", mustString(t, updateApproval, "revision"), idempotencyKey(5)).
		expect(t, http.StatusOK)
	bob = e.userByUsername(a, "bob")
	if mustString(t, bob, "display_name") != "Bob" {
		t.Fatalf("display_name = %v", bob["display_name"])
	}

	// Delete is destructive: once the administrator enables optional 2FA,
	// approving it demands a fresh second factor.
	e.enableTOTP(a.userID)
	deleteReq := a.sign(http.MethodDelete,
		"/api/v1/users/"+bobID+"?expected_revision="+mustString(t, bob, "revision"), "")
	deleteReq.Header.Set("Idempotency-Key", idempotencyKey(6))
	deleted := e.do(deleteReq).expect(t, http.StatusAccepted)
	var deleteOp struct {
		ApprovalID  string `json:"approval_id"`
		OperationID string `json:"operation_id"`
	}
	deleted.decode(t, &deleteOp)
	deleteApproval := e.approval(a, deleteOp.ApprovalID)
	if deleteApproval["requires_mfa"] != true {
		t.Fatalf("requires_mfa = %v", deleteApproval["requires_mfa"])
	}
	e.decide(a, deleteOp.ApprovalID, "approve", mustString(t, deleteApproval, "revision"), idempotencyKey(7)).
		expectProblem(t, http.StatusForbidden, problem.MFARequired)

	// The queued operation can be canceled, and its approval dies with it.
	cancel := a.sign(http.MethodPost, "/api/v1/operations/"+deleteOp.OperationID+"/cancel", `{"reason":"not now"}`)
	cancel.Header.Set("Idempotency-Key", idempotencyKey(8))
	var canceled map[string]any
	e.do(cancel).expect(t, http.StatusOK).decode(t, &canceled)
	if mustString(t, canceled, "status") != "CANCELED" {
		t.Fatalf("canceled operation = %v", canceled["status"])
	}
	if got := e.approval(a, deleteOp.ApprovalID); mustString(t, got, "status") != "CANCELED" {
		t.Fatalf("approval after cancel = %v", got["status"])
	}

	// A service account may reach the REST routes but never decide approvals.
	token := e.serviceToken(a)
	decision := bearer(http.MethodPost, "/api/v1/approvals/"+deleteOp.ApprovalID+"/decision",
		`{"decision":"approve","expected_revision":"1"}`, token)
	decision.Header.Set("Idempotency-Key", idempotencyKey(10))
	e.do(decision).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)

	// A service token is also refused on the session-only routes.
	e.do(bearer(http.MethodGet, "/api/v1/delegations", "", token)).
		expectProblem(t, http.StatusForbidden, problem.PermissionDenied)

	// The approval listings are readable by a service account, but only for its
	// own operations: alice's approval is invisible.
	own := e.do(bearer(http.MethodGet, "/api/v1/approvals", "", token)).expect(t, http.StatusOK)
	var ownPage struct {
		Items []any `json:"items"`
	}
	own.decode(t, &ownPage)
	if len(ownPage.Items) != 0 {
		t.Fatalf("service account saw foreign approvals: %v", ownPage.Items)
	}
	e.do(bearer(http.MethodGet, "/api/v1/approvals/"+deleteOp.ApprovalID, "", token)).
		expectProblem(t, http.StatusNotFound, problem.NotFound)
}

// TestUserCreateResultHasNoEnrollmentToken runs host.users.create to the end
// and checks that the enrollment token reaches neither the operation result,
// nor any reader of it, nor the stored operation and idempotent responses
// (AUTH-06): the result only says that the new user still has to enroll.
func TestUserCreateResultHasNoEnrollmentToken(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	viewer := e.signIn("vera", identity.RoleViewer)
	operationID := e.createApprovedUser(a, "bob", "operator")

	var op map[string]any
	e.do(a.sign(http.MethodGet, "/api/v1/operations/"+operationID, "")).expect(t, http.StatusOK).decode(t, &op)
	if mustString(t, op, "status") != "SUCCEEDED" {
		t.Fatalf("operation = %v", op)
	}
	result, _ := op["result"].(map[string]any)
	if _, ok := result["enrollment_token"]; ok {
		t.Fatalf("the operation result carries the enrollment token: %v", result)
	}
	if result["enrollment_pending"] != true {
		t.Fatalf("enrollment_pending = %v, want true", result["enrollment_pending"])
	}
	if mustString(t, result, "enrollment_expires_at") == "" {
		t.Fatal("enrollment_expires_at is empty")
	}
	user, _ := result["user"].(map[string]any)
	if mustString(t, user, "username") != "bob" {
		t.Fatalf("result user = %v", user)
	}

	// A viewer reads every operation (follow mode) and still never sees one.
	for _, path := range []string{"/api/v1/operations/" + operationID, "/api/v1/operations?limit=200"} {
		body := e.do(viewer.sign(http.MethodGet, path, "")).expect(t, http.StatusOK).body
		if bytes.Contains(body, []byte("enrollment_token")) {
			t.Fatalf("GET %s showed an enrollment token to a viewer: %s", path, body)
		}
	}
	if hits := e.storedIn("enrollment_token"); len(hits) > 0 {
		t.Fatalf("an enrollment token is stored in %v", hits)
	}
}

// TestUserCreateResultNeedsActionPermission covers the defense in depth of the
// operation reads: every person sees every operation, but its result only goes
// to the actor that started it and to callers holding the permission of its
// action.
func TestUserCreateResultNeedsActionPermission(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	admin := e.signIn("dora", identity.RoleAdmin)
	operator := e.signIn("otto", identity.RoleOperator)
	viewer := e.signIn("vera", identity.RoleViewer)
	operationID := e.createApprovedUser(a, "bob", "operator")

	// hasResult reports whether a caller sees the result, and checks that the
	// single read and the list agree.
	hasResult := func(who auth) bool {
		t.Helper()
		var op map[string]any
		e.do(who.sign(http.MethodGet, "/api/v1/operations/"+operationID, "")).expect(t, http.StatusOK).decode(t, &op)
		_, got := op["result"]
		var page struct {
			Items []map[string]any `json:"items"`
		}
		e.do(who.sign(http.MethodGet, "/api/v1/operations?limit=200", "")).expect(t, http.StatusOK).decode(t, &page)
		listed, found := false, false
		for _, item := range page.Items {
			if item["operation_id"] == operationID {
				_, listed = item["result"]
				found = true
			}
		}
		if !found {
			t.Fatalf("operation %s is not listed", operationID)
		}
		if got != listed {
			t.Fatalf("get shows the result: %v, the list: %v", got, listed)
		}
		return got
	}
	if !hasResult(a) {
		t.Fatal("the initiator does not see the result")
	}
	if !hasResult(admin) {
		t.Fatal("another administrator does not see the result")
	}
	if hasResult(operator) {
		t.Fatal("an operator without host.users:create sees the result")
	}
	if hasResult(viewer) {
		t.Fatal("a viewer sees the result")
	}

	// The initiator keeps the result of their own operation after losing the
	// permission.
	alice, err := e.c.Identity().User(t.Context(), a.userID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	demoted := identity.RoleViewer
	if err := e.c.DB().Update(t.Context(), func(tx *storage.Tx) error {
		_, err := e.c.Identity().UpdateUser(t.Context(), tx, identity.UpdateUserInput{
			UserID: a.userID, ExpectedRevision: alice.Revision, Role: &demoted,
		})
		return err
	}); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if !hasResult(a) {
		t.Fatal("the initiator lost the result after a demotion")
	}
}

// TestEnrollmentTokenEndpointHumanOnly: only a human browser session of an
// administrator with a fresh second factor may issue an enrollment link; the
// token is shown in that response only and works exactly like the link a user
// redeems.
func TestEnrollmentTokenEndpointHumanOnly(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	secret, _ := e.enableTOTP(a.userID)
	bob := e.insertUser("bob", identity.RoleOperator, "")
	path := "/api/v1/users/" + bob + "/enrollment-token"

	// An AI operator and a service account are refused by the credential
	// policy, a viewer by RBAC.
	create := a.sign(http.MethodPost, "/api/v1/delegations", `{"label":"claude desktop"}`)
	create.Header.Set("Idempotency-Key", idempotencyKey(1))
	var delegation map[string]any
	e.do(create).expect(t, http.StatusCreated).decode(t, &delegation)
	tokens := map[string]string{
		"delegation":      mustString(t, delegation, "token"),
		"service account": e.serviceToken(a),
	}
	for name, token := range tokens {
		req := bearer(http.MethodPost, path, `{}`, token)
		req.Header.Set("Idempotency-Key", idempotencyKey(2))
		if got := e.do(req); got.status != http.StatusForbidden {
			t.Fatalf("%s: status = %d, want 403 (body %s)", name, got.status, got.body)
		}
	}
	viewer := e.signIn("vera", identity.RoleViewer)
	e.issueEnrollment(viewer, bob, `{}`, 3).expectProblem(t, http.StatusForbidden, problem.PermissionDenied)

	// The administrator gets the token once; the response must not be cached.
	body := fmt.Sprintf(`{"mfa_code":%q}`, totpAt(secret, 1))
	issued := e.issueEnrollment(a, bob, body, 4).expect(t, http.StatusOK)
	if got := issued.header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	var link map[string]any
	issued.decode(t, &link)
	token := mustString(t, link, "enrollment_token")
	if len(token) < 32 {
		t.Fatalf("enrollment token too short: %d", len(token))
	}
	if mustString(t, link, "user_id") != bob {
		t.Fatalf("user_id = %v, want %s", link["user_id"], bob)
	}
	expires := mustString(t, link, "expires_at")

	// The idempotent replay answers again, without the token.
	replayed := e.issueEnrollment(a, bob, body, 4).expect(t, http.StatusOK)
	if replayed.header.Get("Idempotency-Replayed") != "true" {
		t.Fatal("replay did not set Idempotency-Replayed")
	}
	var again map[string]any
	replayed.decode(t, &again)
	if _, ok := again["enrollment_token"]; ok {
		t.Fatalf("the replay repeated the token: %s", replayed.body)
	}
	if mustString(t, again, "user_id") != bob || mustString(t, again, "expires_at") != expires {
		t.Fatalf("replay = %v, want the original user_id and expires_at", again)
	}

	// The token is a working enrollment link: bob chooses a password and signs in.
	if _, err := e.c.Identity().RedeemEnrollmentToken(t.Context(), token, "a brand new passphrase"); err != nil {
		t.Fatalf("redeem: %v", err)
	}
	e.login("bob", "a brand new passphrase")
}

// TestEnrollmentTokenRequiresFreshMFA: the session must have passed a second
// factor recently, or the request carries a current TOTP code. A missing or
// wrong code is 403 MFA_REQUIRED, never a 401 that would end the session in
// the Shell.
func TestEnrollmentTokenRequiresFreshMFA(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	bob := e.insertUser("bob", identity.RoleOperator, "")

	// 2FA is optional: an account without 2FA enabled can issue enrollment links
	// without being forced to set up TOTP, while malformed mfa_code is still validated.
	malformed := e.issueEnrollment(a, bob, `{"mfa_code":"12345"}`, 3).
		expectProblem(t, http.StatusBadRequest, problem.ValidationFailed)
	if len(malformed.Violations) == 0 || malformed.Violations[0].Pointer != "/mfa_code" {
		t.Fatalf("violations = %+v", malformed.Violations)
	}
	e.issueEnrollment(a, bob, `{}`, 1).expect(t, http.StatusOK)

	// Once 2FA is enabled on the account, issuing enrollment links enforces fresh MFA.
	secret, recovery := e.enableTOTP(a.userID)
	e.issueEnrollment(a, bob, fmt.Sprintf(`{"mfa_code":%q}`, wrongTOTP(secret)), 4).
		expectProblem(t, http.StatusForbidden, problem.MFARequired)
	// This session never passed the second factor.
	e.issueEnrollment(a, bob, `{}`, 5).expectProblem(t, http.StatusForbidden, problem.MFARequired)

	// A session that passed it at login is fresh without a code.
	fresh := e.loginWithRecoveryCode(adminUser, recovery[0])
	e.issueEnrollment(fresh, bob, `{}`, 6).expect(t, http.StatusOK)
	// A current code makes one request fresh on a session that is not.
	e.issueEnrollment(a, bob, fmt.Sprintf(`{"mfa_code":%q}`, totpAt(secret, 1)), 7).expect(t, http.StatusOK)
}

// TestEnrollmentTokenOnlyForUsersWithoutPassword: an enrollment link sets the
// first password. For an account that has one (the administrator's own
// included) it would let whoever holds the link take the account over.
func TestEnrollmentTokenOnlyForUsersWithoutPassword(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	_, recovery := e.enableTOTP(a.userID)
	fresh := e.loginWithRecoveryCode(adminUser, recovery[0])
	carol := e.insertUser("carol", identity.RoleOperator, adminPass)

	e.issueEnrollment(fresh, carol, `{}`, 1).expectProblem(t, http.StatusConflict, problem.StateConflict)
	e.issueEnrollment(fresh, a.userID, `{}`, 2).expectProblem(t, http.StatusConflict, problem.StateConflict)
	e.issueEnrollment(fresh, "usr_does_not_exist", `{}`, 3).expectProblem(t, http.StatusNotFound, problem.NotFound)
}

// TestEnrollmentTokenNeverStored: the token goes to the response and nowhere
// else, while the audit log still records who issued a link for whom.
func TestEnrollmentTokenNeverStored(t *testing.T) {
	var logs syncBuffer
	e := newEnvWith(t, func(d *api.Deps) {
		d.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	a := e.setupAdmin(adminUser)
	_, recovery := e.enableTOTP(a.userID)
	fresh := e.loginWithRecoveryCode(adminUser, recovery[0])
	bob := e.insertUser("bob", identity.RoleOperator, "")

	var link map[string]any
	e.issueEnrollment(fresh, bob, `{}`, 1).expect(t, http.StatusOK).decode(t, &link)
	token := mustString(t, link, "enrollment_token")
	if hits := e.storedIn(token); len(hits) > 0 {
		t.Fatalf("the enrollment token is stored in %v", hits)
	}
	if strings.Contains(logs.String(), token) {
		t.Fatal("the enrollment token reached the log")
	}

	var audited int
	if err := e.c.DB().Reader().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM audit_log WHERE action = 'enrollment_token.issue' AND subject = ?
		 AND actor_kind = 'human' AND actor_id = ? AND outcome = 'success' AND request_id <> ''`,
		"users/"+bob, a.userID).Scan(&audited); err != nil {
		t.Fatalf("query audit log: %v", err)
	}
	if audited != 1 {
		t.Fatalf("audit rows = %d, want 1", audited)
	}
}
