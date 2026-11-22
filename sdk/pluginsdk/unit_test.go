// SPDX-License-Identifier: Apache-2.0

package pluginsdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qwq-panel/qwq/sdk/abi"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

func TestValidateSubject(t *testing.T) {
	valid := []string{
		"a", "greeting", "inbounds/vless-in~1", "a.b_c-d", "A0._~-", "a/b/c",
		strings.Repeat("x", 128),
	}
	for _, subject := range valid {
		if err := ValidateSubject(subject); err != nil {
			t.Errorf("ValidateSubject(%q) = %v", shorten(subject), err)
		}
	}
	invalid := []string{
		"", "/a", "a/", "a//b", ".", "..", "a/../b", "./a", "a b", "订阅",
		strings.Repeat("x", 129), "a\nb", "a~b/c d",
	}
	for _, subject := range invalid {
		err := ValidateSubject(subject)
		if err == nil {
			t.Errorf("ValidateSubject(%q) accepted", shorten(subject))
			continue
		}
		if CodeOf(err) != "PROTOCOL_ERROR" {
			t.Errorf("ValidateSubject(%q) code = %q", shorten(subject), CodeOf(err))
		}
	}
}

func shorten(s string) string {
	if len(s) > 20 {
		return s[:20] + "…"
	}
	return s
}

func TestValidatePlan(t *testing.T) {
	ok := Plan{Changes: []PlannedChange{{Kind: ChangeCreate, Subject: "a", Description: "d"}},
		Preconditions: []Precondition{{Subject: "a"}}}
	if err := validatePlan(ok); err != nil {
		t.Fatalf("valid plan: %v", err)
	}
	for name, plan := range map[string]Plan{
		"bad subject":      {Changes: []PlannedChange{{Kind: ChangeCreate, Subject: "../x"}}},
		"no kind":          {Changes: []PlannedChange{{Subject: "a"}}},
		"long text":        {Changes: []PlannedChange{{Kind: ChangeCreate, Subject: "a", Description: strings.Repeat("x", 201)}}},
		"bad before json":  {Changes: []PlannedChange{{Kind: ChangeCreate, Subject: "a", Before: []byte("{")}}},
		"bad precondition": {Preconditions: []Precondition{{Subject: "a b"}}},
	} {
		if err := validatePlan(plan); err == nil {
			t.Errorf("%s: validated", name)
		}
	}
}

func TestReadMemoryLimit(t *testing.T) {
	cases := []struct {
		raw   string
		bytes int64
		set   bool
		ok    bool
	}{
		{"", 0, false, true},
		{"off", 0, false, true},
		{"0", 0, true, true},
		{"123", 123, true, true},
		{"1B", 1, true, true},
		{"1KiB", 1024, true, true},
		{"13MiB", 13 << 20, true, true},
		{"1GiB", 1 << 30, true, true},
		{"1TiB", 1 << 40, true, true},
		{"13MB", 0, false, false},
		{"1.5GiB", 0, false, false},
		{"-1", 0, false, false},
		{"8MiB ", 0, false, false},
		{"max", 0, false, false},
	}
	for _, c := range cases {
		got, err := ReadMemoryLimit(func(string) string { return c.raw })
		if (err == nil) != c.ok {
			t.Errorf("%q: error = %v", c.raw, err)
			continue
		}
		if !c.ok {
			continue
		}
		if got.Set != c.set || got.Bytes != c.bytes || got.Raw != c.raw {
			t.Errorf("%q: %+v", c.raw, got)
		}
	}
}

// stubRegistrar satisfies grpc.ServiceRegistrar for Serve tests that fail
// before registration.
type stubRegistrar struct{}

func (stubRegistrar) RegisterService(*grpc.ServiceDesc, any) {}

func TestServeRejectsMalformedMemoryLimit(t *testing.T) {
	t.Setenv(EnvMemoryLimit, "13MB")
	_, err := Serve(t.Context(), Options{
		Plugin: minimalPlugin{}, Manifest: fixtureManifest(0, nil, nil), Registrar: stubRegistrar{},
	})
	if err == nil || !strings.Contains(err.Error(), EnvMemoryLimit) {
		t.Fatalf("Serve error = %v", err)
	}
}

func TestServeRejectsInvalidOptions(t *testing.T) {
	if _, err := Serve(t.Context(), Options{Manifest: fixtureManifest(0, nil, nil), Registrar: stubRegistrar{}}); err == nil {
		t.Fatal("Serve accepted a nil Plugin")
	}
	if _, err := Serve(t.Context(), Options{Plugin: minimalPlugin{}, Registrar: stubRegistrar{}}); err == nil {
		t.Fatal("Serve accepted an empty manifest")
	}
	if _, err := Serve(t.Context(), Options{Plugin: minimalPlugin{}, Manifest: []byte(`{}`), Registrar: stubRegistrar{}}); err == nil {
		t.Fatal("Serve accepted an invalid manifest")
	}
	if _, err := Serve(t.Context(), Options{Plugin: minimalPlugin{}, Manifest: fixtureManifest(0, nil, nil)}); err == nil {
		t.Fatal("Serve accepted a nil Registrar")
	}
}

func TestServeRejectsNewerABI(t *testing.T) {
	raw := fixtureManifest(abi.Minor+1, nil, nil)
	_, err := Serve(t.Context(), Options{
		Plugin: minimalPlugin{}, Manifest: raw, Registrar: stubRegistrar{},
	})
	if err == nil || !strings.Contains(err.Error(), "ABI") {
		t.Fatalf("Serve error = %v", err)
	}
}

func TestCheckHealthReportsMemoryLimit(t *testing.T) {
	t.Setenv(EnvMemoryLimit, "32MiB")
	env := newEnv(t, minimalPlugin{}, fixtureManifest(0, nil, nil))
	env.initialize("a", nil)
	env.start("a")
	health, err := env.client.CheckHealth(testContext(t), &platformv1.CheckHealthRequest{Context: lifecycleContext("a")})
	if err != nil {
		t.Fatal(err)
	}
	var details struct {
		Memory struct {
			Bytes int64 `json:"gomemlimit_bytes"`
			Set   bool  `json:"gomemlimit_set"`
			MaxMB int64 `json:"memory_max_mb"`
		} `json:"memory"`
	}
	if err := json.Unmarshal(health.GetDetailsJson(), &details); err != nil {
		t.Fatalf("details = %s, %v", health.GetDetailsJson(), err)
	}
	if !details.Memory.Set || details.Memory.Bytes != 32<<20 || details.Memory.MaxMB != 64 {
		t.Fatalf("details = %s", health.GetDetailsJson())
	}
}

func TestErrorHelpers(t *testing.T) {
	e := Errorf("SOME_CODE", "value %d", 7)
	if e.Code != "SOME_CODE" || e.Message != "value 7" || CodeOf(e) != "SOME_CODE" {
		t.Fatalf("Errorf = %+v", e)
	}
	if !IsConflict(fmt.Errorf("wrapped: %w", Errorf("REVISION_CONFLICT", "conflict"))) {
		t.Fatal("IsConflict did not see the wrapped error")
	}
	v := Validation(FieldViolation{Pointer: "/x", Code: "REQUIRED", Message: "required"})
	if v.Code != "VALIDATION_FAILED" || len(v.Violations) != 1 {
		t.Fatalf("Validation = %+v", v)
	}
	pc := PreconditionFailed("greeting", "3")
	var details map[string]string
	if err := json.Unmarshal(pc.DetailsJSON, &details); err != nil || details["subject"] != "greeting" || details["revision"] != "3" {
		t.Fatalf("PreconditionFailed details = %s", pc.DetailsJSON)
	}

	d := errorDetail(v, "zh-CN")
	if d.GetCode() != "VALIDATION_FAILED" || len(d.GetViolations()) != 1 || d.GetViolations()[0].GetPointer() != "/x" {
		t.Fatalf("errorDetail = %v", d)
	}
	if got := errorDetail(errors.New("boom"), "en"); got.GetCode() != "INTERNAL" ||
		strings.Contains(got.GetMessage(), "boom") {
		t.Fatalf("generic error detail = %v", got)
	}
	if got := errorDetail(context.Canceled, "en"); got.GetCode() != "CANCELED" {
		t.Fatalf("canceled detail = %v", got)
	}
	if got := errorDetail(context.DeadlineExceeded, "en"); got.GetCode() != "DEADLINE_EXCEEDED" || !got.GetRetryable() {
		t.Fatalf("deadline detail = %v", got)
	}
	if got := CodeOf(errors.New("plain")); got != "" {
		t.Fatalf("CodeOf(plain) = %q", got)
	}
}

func TestLocalize(t *testing.T) {
	for locale, want := range map[string]string{
		"zh-CN": "中文", "zh": "中文", "en": "english", "": "english", "fr": "english",
	} {
		if got := Localize(locale, "中文", "english"); got != want {
			t.Errorf("Localize(%q) = %q, want %q", locale, got, want)
		}
	}
}

func TestPublicRouteStatus(t *testing.T) {
	if got := statusCodeOf(publicRouteStatus(Errorf("VALIDATION_FAILED", "bad"))); got != codes.InvalidArgument {
		t.Fatalf("validation route status = %v", got)
	}
	if got := statusCodeOf(publicRouteStatus(errors.New("boom"))); got != codes.Internal {
		t.Fatalf("generic route status = %v", got)
	}
}

func statusCodeOf(err error) codes.Code { return status.Code(err) }
