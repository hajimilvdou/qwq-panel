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
