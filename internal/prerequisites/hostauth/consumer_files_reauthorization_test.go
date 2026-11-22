// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package hostauth

import (
	"context"
	"os"
	"testing"

	"github.com/qwq-panel/qwq/internal/prerequisites/consumerfiles"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 两个真实受理 operation；材料同代，消费许可确实换版 ========================

func TestAcceptedReauthorizationStagesSameGenerationWithNewPolicy(t *testing.T) {
	f := newReservationFixture(t)
	reservation := f.reserve(t)
	firstCall, firstContext, _, first, _ := f.confirm(t, reservation)
	material, err := tlsmgr.NewMaterial(f.certificate.Chain, f.certificate.Key)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Clear()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	files, err := consumerfiles.New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	old, err := files.Stage(firstContext, first, material)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := files.Activate(firstContext, nil, old); err != nil {
		t.Fatal(err)
	}
	firstCall.finish()
	f.source.mu.Lock()
	f.source.facts.ConfigRevision = "1"
	f.source.mu.Unlock()
	args := ReserveBindingArgs{CertificateID: fixtureCertificate, Consumer: f.want, ExpectedConfigRevision: "1"}
	f.call = f.f.start(t, f.f.human, "tls.certificates", "bindings.reserve", certificateSubject(fixtureCertificate), stringsDigest('a'), args)
	repeated := f.reserve(t)
	secondCall, secondContext, request, second, _ := f.confirmAttempt(t, repeated, "bind-reconfirmed")
	defer secondCall.finish()
	if first.ID != second.ID || first.Generation != second.Generation || first.Consumer != second.Consumer || first.PolicyRevision == second.PolicyRevision {
		t.Fatal("两个受理 operation 没有产生稳定绑定与同材料代的新许可")
	}
	if _, _, err := f.f.authority.bindingGrant(secondContext, request.Caller); err != nil {
		t.Fatalf("第二次真实消费许可无效：%v", err)
	}
	fresh, err := files.Stage(secondContext, second, material)
	if err != nil {
		t.Fatalf("真实新许可被旧 gN 证明阻断：%v", err)
	}
	for _, wanted := range []consumerfiles.Proof{old, fresh} {
		loaded, err := files.Load(context.Background(), wanted)
		if err != nil {
			t.Fatalf("未保留指定完整许可的材料读取：%v", err)
		}
		loaded.Clear()
	}
	previous, err := files.Activate(secondContext, &old, fresh)
	if err != nil || previous == nil || *previous != old {
		t.Fatalf("真实同代新许可 CAS 丢失前代：%v", err)
	}
}
