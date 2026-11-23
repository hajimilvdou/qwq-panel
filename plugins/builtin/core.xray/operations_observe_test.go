// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/anytls"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/coreproc"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/metrics"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/state"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

func TestObserveMetricsDistinguishesZeroMissingAndExactLargeValues(t *testing.T) {
	f := newApplyFixture(t)
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	metadata, err := f.store.Committed(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int64{"inbound>>>qwq-in-main>>>traffic>>>uplink": 0, "inbound>>>qwq-in-main>>>traffic>>>downlink": math.MaxInt64}
	result, err := metrics.Normalize(metadata.Current.Summary, counts, metrics.Filter{}, "epoch-test", time.Now())
	if err != nil || len(result.Series) != 2 {
		t.Fatal("valid current statistics were not normalized")
	}
	for _, series := range result.Series {
		if series.Kind == "inbound" && (!series.Present || series.UplinkBytes == nil || *series.UplinkBytes != "0" || series.DownlinkBytes == nil || *series.DownlinkBytes != strconv.FormatInt(math.MaxInt64, 10)) {
			t.Fatal("zero or exact large counters were lost")
		}
		if series.Kind == "user" && (series.Present || series.UplinkBytes != nil || series.DownlinkBytes != nil) {
			t.Fatal("missing user counters were fabricated as zero")
		}
		if series.ResetEpoch != "epoch-test" || series.Source != "xray" || series.CollectedAt == "" {
			t.Fatal("series omitted origin and epoch")
		}
	}
}

func TestObserveMetricsRejectsInvalidCountersAndFilters(t *testing.T) {
	f := newApplyFixture(t)
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	metadata, err := f.store.Committed(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, counts := range []map[string]int64{{"inbound>>>qwq-in-main>>>traffic>>>uplink": -1}, {"user>>>qwq-user-unknown>>>traffic>>>uplink": 1}, {"arbitrary-secret-pattern": 1}} {
		if _, err := metrics.Normalize(metadata.Current.Summary, counts, metrics.Filter{}, "epoch", time.Now()); err == nil {
			t.Fatal("untrusted response was accepted")
		}
	}
	for _, payload := range []string{`{"reset":true}`, `{"pattern":".*"}`, `{"ids":null}`, `{"kind":null}`, `{"ids":["alice","alice"]}`, `{"ids":["../secret"]}`, `{"kind":"all"}`, `{"kind":"user","kind":"user"}`} {
		if _, err := decodeObserveInput([]byte(payload)); err == nil {
			t.Fatal("unsafe observe filter was accepted")
		}
	}
}

type fakeCounterProcess struct {
	*fakeApplyProcess
	counts map[string]int64
	err    error
}

func (p *fakeCounterProcess) ReadCounters(ctx context.Context) (coreproc.CounterSnapshot, error) {
	if ctx.Err() != nil {
		return coreproc.CounterSnapshot{}, ctx.Err()
	}
	if p.err != nil {
		return coreproc.CounterSnapshot{}, p.err
	}
	process := p.Snapshot(ctx)
	copy := make(map[string]int64, len(p.counts))
	for name, value := range p.counts {
		copy[name] = value
	}
	return coreproc.CounterSnapshot{Epoch: process.Epoch, Digest: process.Digest, Values: copy}, nil
}

func TestFakeRuntimeObserveKeepsCurrentEpochAndFailsOnAPIError(t *testing.T) {
	f := newApplyFixture(t)
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	process := &fakeCounterProcess{fakeApplyProcess: f.process, counts: map[string]int64{"inbound>>>qwq-in-main>>>traffic>>>uplink": 0, "inbound>>>qwq-in-main>>>traffic>>>downlink": 7}}
	driver := &driverRuntime{store: f.store, process: process, controller: f.engine, trusted: true, coreVersion: state.CoreVersion}
	result, err := driver.observe(t.Context(), metrics.Filter{Kind: "inbound"})
	if err != nil || len(result.Series) != 1 || result.Series[0].ResetEpoch != f.process.Snapshot(t.Context()).Epoch {
		t.Fatal("observe did not preserve the actual current epoch")
	}
	process.err = errors.New("sensitive upstream detail")
	if _, err := driver.observe(t.Context(), metrics.Filter{}); err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("API error was hidden or exposed a diagnostic")
	}
}

func TestFakeSDKObserveFilteringAndRestartEpoch(t *testing.T) {
	f, server := sdkApplyFixture(t)
	process := &fakeCounterProcess{fakeApplyProcess: f.process, counts: map[string]int64{"inbound>>>qwq-in-main>>>traffic>>>uplink": 0, "inbound>>>qwq-in-main>>>traffic>>>downlink": 7}}
	f.driver.process = process
	if terminal := runSDKApply(t, server, "1"); terminal.GetError() != nil {
		t.Fatal("fake apply failed")
	}
	first := decodeReadResult[metrics.Result](t, readInvoke(t, server, "core.observe", `{"kind":"inbound","ids":["main"]}`))
	if len(first.Series) != 1 || !first.Series[0].Present || *first.Series[0].UplinkBytes != "0" {
		t.Fatal("SDK filter lost the real zero")
	}
	missing := decodeReadResult[metrics.Result](t, readInvoke(t, server, "core.observe", `{"kind":"user"}`))
	if len(missing.Series) != 1 || missing.Series[0].Present || missing.Series[0].UplinkBytes != nil {
		t.Fatal("SDK fabricated missing user counters")
	}
	f.changeDesired()
	if _, err := server.ApplyConfig(t.Context(), &pb.ApplyConfigRequest{Context: testContext(), ConfigJson: f.host.config, ProposedRevision: "2"}); err != nil {
		t.Fatal(err)
	}
	if terminal := runSDKApply(t, server, "2"); terminal.GetError() != nil {
		t.Fatal("fake restart apply failed")
	}
	second := decodeReadResult[metrics.Result](t, readInvoke(t, server, "core.observe", `{"kind":"inbound"}`))
	if second.ResetEpoch == first.ResetEpoch {
		t.Fatal("SDK observe reused the old process epoch")
	}
	process.err = errors.New("private diagnostic")
	if response := readInvoke(t, server, "core.observe", `{}`); response.GetError().GetCode() != "CORE_API_UNAVAILABLE" || len(response.GetPayloadJson()) != 0 {
		t.Fatal("unavailable statistics were reported as success")
	}
}

func TestObserveMetricsV2MultiInboundAndAPIStatsIgnored(t *testing.T) {
	summary := &state.V2IntentSummary{
		SchemaVersion: "2",
		OutboundType:  "direct",
		RefsDigest:    "sha256:" + strings.Repeat("b", 64),
		Profiles: []state.PublicProfileSummary{
			{
				ID:         "hy2-edge",
				Enabled:    true,
				Listen:     "0.0.0.0",
				Port:       443,
				Protocol:   "hysteria2",
				BindingRef: "bind-01",
				ServerName: "edge.example.com",
				UserIDs:    []string{"alice"},
			},
			{
				ID:       "vless-edge",
				Enabled:  true,
				Listen:   "0.0.0.0",
				Port:     8443,
				Protocol: "vless",
				UserIDs:  []string{"alice", "bob"},
			},
		},
	}
	counters := map[string]int64{
		"inbound>>>qwq-api-in>>>traffic>>>uplink":        999,
		"inbound>>>qwq-in-hy2-edge>>>traffic>>>uplink":   100,
		"inbound>>>qwq-in-hy2-edge>>>traffic>>>downlink": 200,
		"user>>>qwq-user-alice>>>traffic>>>uplink":       300,
		"user>>>qwq-user-alice>>>traffic>>>downlink":     400,
	}
	res, err := metrics.NormalizeV2(summary, counters, metrics.Filter{}, "epoch-v2", time.Now())
	if err != nil {
		t.Fatalf("NormalizeV2 failed: %v", err)
	}
	if len(res.Series) != 4 {
		t.Fatalf("expected 2 inbounds + 2 unique users = 4 series, got %d", len(res.Series))
	}
	var foundAlice, foundBob bool
	for _, s := range res.Series {
		if s.Kind == "user" && s.ID == "alice" {
			foundAlice = true
			if !s.Present || s.UplinkBytes == nil || *s.UplinkBytes != "300" || s.DownlinkBytes == nil || *s.DownlinkBytes != "400" {
				t.Fatalf("unexpected alice series: %+v", s)
			}
		}
		if s.Kind == "user" && s.ID == "bob" {
			foundBob = true
			if s.Present || s.UplinkBytes != nil || s.DownlinkBytes != nil {
				t.Fatalf("missing bob counters should stay nil: %+v", s)
			}
		}
	}
	if !foundAlice || !foundBob {
		t.Fatalf("missing expected user series: alice=%v bob=%v", foundAlice, foundBob)
	}
}

type fakeAnyTLSManager struct {
	counters map[string]int64
}

func (f *fakeAnyTLSManager) StartAll(context.Context, []anytls.ProfileSpec) error { return nil }
func (f *fakeAnyTLSManager) StopAll(time.Duration)                                {}
func (f *fakeAnyTLSManager) ReloadCertificate(string, string, []byte, []byte) (bool, error) {
	return true, nil
}
func (f *fakeAnyTLSManager) Counters() map[string]int64 {
	out := make(map[string]int64, len(f.counters))
	for k, v := range f.counters {
		out[k] = v
	}
	return out
}
func (f *fakeAnyTLSManager) Status() (bool, string) { return true, "" }
func (f *fakeAnyTLSManager) IsRunning(string) bool  { return true }

// TestObserveAnyTLSEpochSwitchNeverDoubleCounts 回归 PLG-FIX-06：
// 模拟 AnyTLS 累计跑流 100 MiB 后 Xray 子进程重启并切换 ResetEpoch，
// 断言新纪元首包 Observe 仅汇报切换窗口内的新增增量（0 或微小增量），绝不重报 100 MiB。
func TestObserveAnyTLSEpochSwitchNeverDoubleCounts(t *testing.T) {
	f := newApplyFixture(t)
	if _, err := f.engine.Execute(t.Context(), f.request()); err != nil {
		t.Fatal(err)
	}
	committed, err := f.store.Committed(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	committed.Current.Summary = nil
	committed.Current.SummaryV2 = &state.V2IntentSummary{
		SchemaVersion: "2",
		OutboundType:  "direct",
		RefsDigest:    "sha256:" + strings.Repeat("c", 64),
		Profiles: []state.PublicProfileSummary{
			{
				ID:         "anytls-edge",
				Enabled:    true,
				Listen:     "0.0.0.0",
				Port:       443,
				Protocol:   "anytls",
				BindingRef: "bind-anytls",
				ServerName: "edge.example.com",
				UserIDs:    []string{"alice"},
			},
		},
	}
	if err := f.store.Commit(t.Context(), committed); err != nil {
		t.Fatal(err)
	}

	const hundredMiB int64 = 100 * 1024 * 1024
	fakeAnyTLS := &fakeAnyTLSManager{
		counters: map[string]int64{
			"inbound>>>qwq-in-anytls-edge>>>traffic>>>uplink":   hundredMiB,
			"inbound>>>qwq-in-anytls-edge>>>traffic>>>downlink": hundredMiB,
			"user>>>qwq-user-alice>>>traffic>>>uplink":          hundredMiB,
			"user>>>qwq-user-alice>>>traffic>>>downlink":        hundredMiB,
		},
	}
	process := &fakeCounterProcess{
		fakeApplyProcess: f.process,
		counts:           map[string]int64{},
	}
	driver := &driverRuntime{
		store:         f.store,
		process:       process,
		anytls:        fakeAnyTLS,
		anytlsAligner: anytls.NewLosslessEpochAligner(),
		controller:    f.engine,
		trusted:       true,
		coreVersion:   state.CoreVersion,
	}

	// 1. 纪元 1：首次观测，准确汇报 100 MiB
	obs1, err := driver.observe(t.Context(), metrics.Filter{Kind: "user", IDs: []string{"alice"}})
	if err != nil || len(obs1.Series) != 1 || !obs1.Series[0].Present {
		t.Fatalf("epoch-1 observe failed: err=%v series=%+v", err, obs1.Series)
	}
	if *obs1.Series[0].UplinkBytes != strconv.FormatInt(hundredMiB, 10) || *obs1.Series[0].DownlinkBytes != strconv.FormatInt(hundredMiB, 10) {
		t.Fatalf("epoch-1 expected 100 MiB, got up=%v down=%v", *obs1.Series[0].UplinkBytes, *obs1.Series[0].DownlinkBytes)
	}

	// 2. Xray 重启切换 Epoch；期间 AnyTLS 仅有 4096B 上行与 8192B 下行真实增量（累计值仍 > 100 MiB）
	f.process.mu.Lock()
	f.process.snapshot.Epoch = obs1.ResetEpoch + "-restarted"
	f.process.mu.Unlock()
	fakeAnyTLS.counters["inbound>>>qwq-in-anytls-edge>>>traffic>>>uplink"] = hundredMiB + 4096
	fakeAnyTLS.counters["inbound>>>qwq-in-anytls-edge>>>traffic>>>downlink"] = hundredMiB + 8192
	fakeAnyTLS.counters["user>>>qwq-user-alice>>>traffic>>>uplink"] = hundredMiB + 4096
	fakeAnyTLS.counters["user>>>qwq-user-alice>>>traffic>>>downlink"] = hundredMiB + 8192

	obs2, err := driver.observe(t.Context(), metrics.Filter{Kind: "user", IDs: []string{"alice"}})
	if err != nil || len(obs2.Series) != 1 || !obs2.Series[0].Present {
		t.Fatalf("epoch-2 observe failed: err=%v series=%+v", err, obs2.Series)
	}
	if obs2.ResetEpoch == obs1.ResetEpoch {
		t.Fatalf("expected switched reset epoch, got %q", obs2.ResetEpoch)
	}
	if *obs2.Series[0].UplinkBytes != "4096" || *obs2.Series[0].DownlinkBytes != "8192" {
		t.Fatalf("epoch-2 double-counted historical AnyTLS traffic! got up=%s down=%s want 4096/8192", *obs2.Series[0].UplinkBytes, *obs2.Series[0].DownlinkBytes)
	}

	// 3. 再次重启切换 Epoch 且期间无任何新流量，断言汇报 0 而非 100 MiB
	f.process.mu.Lock()
	f.process.snapshot.Epoch = obs2.ResetEpoch + "-again"
	f.process.mu.Unlock()

	obs3, err := driver.observe(t.Context(), metrics.Filter{Kind: "user", IDs: []string{"alice"}})
	if err != nil || len(obs3.Series) != 1 || !obs3.Series[0].Present {
		t.Fatalf("epoch-3 observe failed: err=%v series=%+v", err, obs3.Series)
	}
	if *obs3.Series[0].UplinkBytes != "0" || *obs3.Series[0].DownlinkBytes != "0" {
		t.Fatalf("epoch-3 expected 0/0 after idle epoch switch, got up=%s down=%s", *obs3.Series[0].UplinkBytes, *obs3.Series[0].DownlinkBytes)
	}
}
