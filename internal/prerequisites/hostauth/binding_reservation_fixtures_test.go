// SPDX-License-Identifier: AGPL-3.0-only

package hostauth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
)

// ======================== 授权计划/配置事实 fixture，不代替真实适配器 ========================

type reservationSourceFixture struct {
	mu       sync.Mutex
	facts    ConsumerReservationFacts
	calls    int
	origin   Invocation
	deadline time.Time
	before   func(context.Context)
}

func (s *reservationSourceFixture) AuthorizeReservation(ctx context.Context, origin Invocation, _ certificates.Consumer) (ConsumerReservationFacts, error) {
	s.mu.Lock()
	s.calls++
	s.origin = origin
	s.deadline, _ = ctx.Deadline()
	facts, before := s.facts, s.before
	s.mu.Unlock()
	if before != nil {
		before(ctx)
	}
	if err := ctx.Err(); err != nil {
		return ConsumerReservationFacts{}, err
	}
	return facts, nil
}

type reservationFixture struct {
	f           *authorityFixture
	call        *fixtureCall
	want        certificates.Consumer
	source      *reservationSourceFixture
	certificate testsupport.Certificate
}

func newReservationFixture(t *testing.T) reservationFixture {
	t.Helper()
	f := newAuthorityFixture(t)
	certificate := signedHostCertificate(t, f)
	t.Cleanup(certificate.Clear)
	initial, _, _ := f.importCertificate(t, certificate, fixtureCertificate, "reservation-certificate")
	initial.finish()
	want := certificates.Consumer{PluginID: "core.xray", ProfileID: "h2-first", NodeID: "local", SNI: "proxy.example.test", Purpose: "proxy.hysteria2"}
	source := &reservationSourceFixture{facts: ConsumerReservationFacts{Consumer: want, ConfigRevision: "0", PluginVersion: "0.2.0+fixture"}}
	f.authority.reservations = source
	args := ReserveBindingArgs{CertificateID: fixtureCertificate, Consumer: want, ExpectedConfigRevision: "0"}
	call := f.start(t, f.human, "tls.certificates", "bindings.reserve", certificateSubject(fixtureCertificate), stringsDigest('a'), args)
	return reservationFixture{f: f, call: call, want: want, source: source, certificate: certificate}
}

func (f reservationFixture) reserve(t *testing.T) BindingReservation {
	t.Helper()
	result, err := f.f.authority.ReserveBinding(f.call.ctx, fixtureCertificate, stringsDigest('a'))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func (f reservationFixture) confirm(t *testing.T, reservation BindingReservation) (*fixtureCall, context.Context, certificates.BindRequest, certificates.HostBinding, *consumerSourceFixture) {
	t.Helper()
	return f.confirmAttempt(t, reservation, "bind-reserved")
}

// confirmAttempt 复用原真实确认路径，允许新 operation 使用独立 attempt。
func (f reservationFixture) confirmAttempt(t *testing.T, reservation BindingReservation, attemptID string) (*fixtureCall, context.Context, certificates.BindRequest, certificates.HostBinding, *consumerSourceFixture) {
	t.Helper()
	f.call.finish()
	source := &consumerSourceFixture{facts: ConsumerFacts{Consumer: f.want, ConfigRevision: "1", PluginVersion: "0.2.0+fixture", BindingRef: reservation.BindingRef}}
	f.f.authority.consumers = source
	args := BindCertificateArgs{CertificateID: fixtureCertificate, BindingRef: reservation.BindingRef, AttemptID: attemptID, Generation: 1}
	call := f.f.start(t, f.f.human, "tls.certificates", "bindings.bind", certificateSubject(fixtureCertificate), stringsDigest('a'), args)
	ctx, _, err := f.f.authority.BindingContext(call.ctx, fixtureCertificate, stringsDigest('a'))
	if err != nil {
		t.Fatal(err)
	}
	request, err := f.f.authority.AcceptedBindRequest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	host, err := f.f.authority.ConfirmConsumerBinding(ctx, request.Caller, request.CertificateID, request.Generation, request.Consumer)
	if err != nil {
		t.Fatal(err)
	}
	return call, ctx, request, host, source
}
