// SPDX-License-Identifier: AGPL-3.0-only

package capability

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/contextbudget"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
	certificatesv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/certificates/v1"
	dnsv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/dns/v1"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestTasksCancelPreservesHostauthContextDuringWorkerCleanup(t *testing.T) {
	f := newTaskFixture(t)
	workerEntered := make(chan struct{})
	cleanupChecked := make(chan error, 1)

	exec := taskExecutorFunc(func(ctx context.Context, _ TaskKind, _, _, _ string, _ certificates.Progress) (certificates.View, error) {
		close(workerEntered)
		<-ctx.Done()
		// 模拟 ACME worker 退出后在 defer 中使用 contextbudget.Detached 执行 30s TXT 清理对账：
		// 此时 execution 不得已被提前 stop() 置为 released！
		detached, stop := contextbudget.Detached(ctx, 5*time.Second)
		defer stop()
		_, invErr := f.authority.CurrentInvocation(detached)
		cleanupChecked <- invErr
		return certificates.View{}, ctx.Err()
	})

	pool := f.pool(t, exec, 2)
	callCtx, args := f.testCall(t, "cert-clean", "attempt-clean")
	view, err := pool.Submit(callCtx, TestTask, args.CertificateID, args.AttemptID, "absent")
	if err != nil {
		t.Fatal(err)
	}
	awaitTaskSignal(t, workerEntered)

	cancelCtx := f.start(t, "tasks.cancel", "plugins/tls.certificates/resources/tasks/"+view.Id, "", hostauth.TaskArgs{
		TaskID: view.Id,
	})
	if _, err := pool.Cancel(cancelCtx, view.Id); err != nil {
		t.Fatalf("Tasks.Cancel = %v", err)
	}

	if cleanupErr := <-cleanupChecked; cleanupErr != nil {
		t.Fatalf("worker cleanup lost hostauth context prematurely on Cancel: %v", cleanupErr)
	}
	drainTasks(t, pool, "")
}

func TestDNSReadSnapshotAllowsUnderscoreCNAMETargetsAndLongDKIMTXT(t *testing.T) {
	scope := dns.Scope{
		ProviderID: "prov-cf",
		Kind:       dns.Cloudflare,
		ZoneID:     "0123456789abcdef0123456789abcdef",
		ZoneName:   "example.com",
		Revision:   "rev_01",
	}
	acmRec, err := dns.CanonicalRecord(scope, dns.Record{
		ID:    "rec-acm",
		Type:  dns.CNAME,
		Name:  "_abc123.example.com",
		Value: "_xyz987.acm-validations.aws",
		TTL:   300,
	})
	if err != nil || acmRec.Value != "_xyz987.acm-validations.aws" {
		t.Fatalf("CanonicalRecord rejected underscore CNAME target: %v", err)
	}

	longDKIM, err := dns.CanonicalRecord(scope, dns.Record{
		ID:    "rec-dkim-4096",
		Type:  dns.TXT,
		Name:  "default._domainkey.example.com",
		Value: strings.Repeat("A", 3000),
		TTL:   300,
	})
	if err != nil || len(longDKIM.Value) != 3000 {
		t.Fatalf("CanonicalRecord rejected >2048B read-only DKIM TXT: %v", err)
	}
}

func TestForwarderRejectsMismatchedCallerOrUnknownFields(t *testing.T) {
	var nilFwd *Forwarder
	_, err := nilFwd.Forward(context.Background(), hostsvc.CapabilityCall{
		PluginID:   "other.plugin",
		InstanceID: "default",
		Service:    "dns",
		Method:     "ListProviders",
		Verb:       "dns.ListProviders",
		Capability: "dns.read",
		Scope:      "self",
		Request:    &dnsv1.ListProvidersRequest{Context: &platformv1.HostCallContext{}},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil forwarder expected InvalidArgument, got %v", err)
	}

	bv := &certificatesv1.BindingView{PreviousGeneration: 3}
	if bv.GetPreviousGeneration() != 3 {
		t.Fatal("BindingView.previous_generation field 11 not generated")
	}
}
