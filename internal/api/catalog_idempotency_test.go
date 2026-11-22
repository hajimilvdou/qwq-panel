// SPDX-License-Identifier: AGPL-3.0-only

package api_test

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/identity"
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/storage"
)

// ======================== 同键并发只能创建一个委托 ========================

func TestCatalogReplayConcurrentDelegation(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	unblock, before := holdCatalogWriter(t, e, nil)
	answers := make(chan response, 2)
	for range 2 {
		go func() {
			req := a.sign(http.MethodPost, "/api/v1/delegations", `{"label":"same invocation"}`)
			req.Header.Set("Idempotency-Key", idempotencyKey(701))
			answers <- e.do(req)
		}()
	}
	// 新登录会话未到 touchInterval；等待两个业务写入真正进入 SQLite 队列，
	// 明确覆盖旧 lookup/store 之间的窗口，不靠概率性并发或任意长睡眠。
	waitCatalogWriters(t, e, before, 2)
	unblock()
	var id string
	tokens, replays := 0, 0
	for range 2 {
		select {
		case answer := <-answers:
			answer.expect(t, http.StatusCreated)
			body := answer.decodeMap(t)
			got := mustString(t, body, "delegation_id")
			if id != "" && got != id {
				t.Error("the same key created different delegations")
			}
			id = got
			if _, ok := body["token"]; ok {
				tokens++
			}
			if answer.header.Get("Idempotency-Replayed") == "true" {
				replays++
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a concurrent request did not finish")
		}
	}
	if tokens != 1 || replays != 1 {
		t.Errorf("one-time response count=%d replay count=%d, want one each", tokens, replays)
	}
	requireCatalogCount(t, e, "SELECT COUNT(*) FROM delegations", 1)
	requireCatalogCount(t, e, "SELECT COUNT(*) FROM audit_log WHERE action = 'delegation.create'", 1)
}

func TestCatalogReplayRechecksQueuedRole(t *testing.T) {
	e := newEnv(t)
	e.setupAdmin(adminUser)
	userID := e.insertUser("queued-operator", identity.RoleOperator, adminPass)
	a := e.login("queued-operator", adminPass)
	current, err := e.c.Identity().User(t.Context(), userID)
	if err != nil {
		t.Fatal(err)
	}
	role := identity.RoleViewer
	unblock, before := holdCatalogWriter(t, e, func(tx *storage.Tx) error {
		_, err := e.c.Identity().UpdateUser(t.Context(), tx, identity.UpdateUserInput{
			UserID: userID, ExpectedRevision: current.Revision, Role: &role,
		})
		return err
	})
	answers := make(chan response, 1)
	go func() {
		req := a.sign(http.MethodPost, "/api/v1/delegations", `{"label":"must be denied after downgrade"}`)
		req.Header.Set("Idempotency-Key", idempotencyKey(705))
		answers <- e.do(req)
	}()
	waitCatalogWriters(t, e, before, 1)
	unblock()
	select {
	case answer := <-answers:
		answer.expectProblem(t, http.StatusForbidden, problem.PermissionDenied)
	case <-time.After(5 * time.Second):
		t.Fatal("the downgraded request did not finish")
	}
	requireCatalogCount(t, e, "SELECT COUNT(*) FROM delegations", 0)
	requireCatalogCount(t, e, "SELECT COUNT(*) FROM idempotency_keys", 0)
}

func TestCatalogReplayExpiryPreservesFreshKeys(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	create := func(key int, label string) response {
		body := map[string]string{"label": label}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := a.sign(http.MethodPost, "/api/v1/delegations", string(raw))
		req.Header.Set("Idempotency-Key", idempotencyKey(key))
		return e.do(req)
	}
	create(706, "expired").expect(t, http.StatusCreated)
	fresh := create(707, "fresh").expect(t, http.StatusCreated).decodeMap(t)
	if err := e.c.DB().Update(t.Context(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE idempotency_keys SET expires_at = ?
			WHERE principal = ? AND method = 'POST' AND route = '/api/v1/delegations' AND key = ?`,
			storage.FormatTime(tx.Now().Add(-time.Minute)), "human:"+a.userID, idempotencyKey(706))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	replaced := create(706, "replacement").expect(t, http.StatusCreated)
	if replaced.header.Get("Idempotency-Replayed") != "" {
		t.Fatal("an expired key replayed its old response")
	}
	again := create(707, "fresh").expect(t, http.StatusCreated)
	if again.header.Get("Idempotency-Replayed") != "true" ||
		mustString(t, again.decodeMap(t), "delegation_id") != mustString(t, fresh, "delegation_id") {
		t.Fatal("reusing an expired key evicted another fresh key")
	}
	requireCatalogCount(t, e, "SELECT COUNT(*) FROM delegations", 3)
}

// ======================== 宿主重启不能重新发放一次性凭据 ========================

func TestCatalogReplaySurvivesHostRestart(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	create := func() response {
		req := a.sign(http.MethodPost, "/api/v1/delegations", `{"label":"persistent invocation"}`)
		req.Header.Set("Idempotency-Key", idempotencyKey(702))
		return e.do(req)
	}
	first := create().expect(t, http.StatusCreated).decodeMap(t)
	id, token := mustString(t, first, "delegation_id"), mustString(t, first, "token")
	_, recovery := e.enableTOTP(a.userID)
	fresh := e.loginWithRecoveryCode(adminUser, recovery[0])
	userID := e.insertUser("persistent-enrollment", identity.RoleOperator, "")
	link := e.issueEnrollment(fresh, userID, `{}`, 703).expect(t, http.StatusOK).decodeMap(t)
	linkToken, expires := mustString(t, link, "enrollment_token"), mustString(t, link, "expires_at")
	e.reopenCatalogHost()
	delegation := create().expect(t, http.StatusCreated)
	got := delegation.decodeMap(t)
	if delegation.header.Get("Idempotency-Replayed") != "true" || mustString(t, got, "delegation_id") != id {
		t.Error("a host restart repeated delegation creation instead of replaying it")
	}
	if _, ok := got["token"]; ok {
		t.Error("a restarted host replayed the delegation token")
	}
	enrollment := e.issueEnrollment(fresh, userID, `{}`, 703).expect(t, http.StatusOK)
	got = enrollment.decodeMap(t)
	if enrollment.header.Get("Idempotency-Replayed") != "true" || mustString(t, got, "expires_at") != expires {
		t.Error("a host restart repeated enrollment issuance instead of replaying it")
	}
	if _, ok := got["enrollment_token"]; ok {
		t.Error("a restarted host replayed the enrollment token")
	}
	for _, secret := range []string{token, linkToken} {
		if len(e.storedIn(secret)) != 0 {
			t.Error("a one-time credential reached public persistent columns")
		}
	}
	requireCatalogCount(t, e, "SELECT COUNT(*) FROM delegations", 1)
	requireCatalogCount(t, e, "SELECT COUNT(*) FROM idempotency_keys WHERE state = 'completed'", 2)
}

// ======================== 回放写入失败必须回滚领域和审计 ========================

func TestCatalogReplayCommitFailureRollsBackCreation(t *testing.T) {
	e := newEnv(t)
	a := e.setupAdmin(adminUser)
	exec := func(query string) {
		t.Helper()
		if err := e.c.DB().Update(t.Context(), func(tx *storage.Tx) error {
			_, err := tx.ExecContext(t.Context(), query)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE TRIGGER fail_catalog_replay BEFORE UPDATE OF response_body ON idempotency_keys
		WHEN NEW.route = '/api/v1/delegations' BEGIN SELECT RAISE(ABORT, 'TEST-ONLY-replay-failure'); END`)
	create := func() response {
		req := a.sign(http.MethodPost, "/api/v1/delegations", `{"label":"atomic invocation"}`)
		req.Header.Set("Idempotency-Key", idempotencyKey(704))
		return e.do(req)
	}
	if create().status < http.StatusInternalServerError {
		t.Error("the API committed a delegation without its durable replay")
	}
	requireCatalogCount(t, e, "SELECT COUNT(*) FROM delegations", 0)
	requireCatalogCount(t, e, "SELECT COUNT(*) FROM audit_log WHERE action = 'delegation.create'", 0)
	requireCatalogCount(t, e, "SELECT COUNT(*) FROM event_journal WHERE subject LIKE 'delegations/%'", 0)
	requireCatalogCount(t, e, "SELECT COUNT(*) FROM idempotency_keys", 0)
	exec("DROP TRIGGER fail_catalog_replay")
	create().expect(t, http.StatusCreated)
	requireCatalogCount(t, e, "SELECT COUNT(*) FROM delegations", 1)
}

func requireCatalogCount(t *testing.T, e *env, query string, want int) {
	t.Helper()
	var count int
	if err := e.c.DB().Reader().QueryRowContext(t.Context(), query).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Errorf("durable row count=%d, want %d for %s", count, want, query)
	}
}

// ======================== 用真实写连接构造可控的事务排队窗口 ========================

func holdCatalogWriter(t *testing.T, e *env, change func(*storage.Tx) error) (func(), int64) {
	t.Helper()
	ready, release := make(chan struct{}), make(chan struct{})
	writer := make(chan error, 1)
	before := e.c.DB().Stats().Write.WaitCount
	go func() {
		writer <- e.c.DB().Update(t.Context(), func(tx *storage.Tx) error {
			close(ready)
			<-release
			if change != nil {
				return change(tx)
			}
			return nil
		})
	}()
	select {
	case <-ready:
	case err := <-writer:
		t.Fatalf("write barrier failed: %v", err)
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the write barrier did not start")
	}
	var once sync.Once
	unblock := func() {
		once.Do(func() {
			close(release)
			if err := <-writer; err != nil {
				t.Error(err)
			}
		})
	}
	t.Cleanup(unblock)
	return unblock, before
}

func waitCatalogWriters(t *testing.T, e *env, before int64, count int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for e.c.DB().Stats().Write.WaitCount < before+int64(count) {
		if time.Now().After(deadline) {
			t.Fatal("requests did not reach the write queue")
		}
		time.Sleep(time.Millisecond)
	}
}
