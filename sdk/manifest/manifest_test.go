// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestRoundTrip decodes every accepted fixture into Manifest, encodes it again
// and compares the meaning with the input. A field missing from the struct, a
// wrong tag or a lossy omitempty shows up as a difference.
func TestRoundTrip(t *testing.T) {
	needAPI(t)
	n := 0
	for _, c := range loadCases(t) {
		if c.Expect != "accept" {
			continue
		}
		raw, err := buildInput(c)
		if err != nil {
			t.Fatal(err)
		}
		m, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		want, derr := decodeStrict(raw)
		if derr != nil {
			t.Fatal(derr)
		}
		got, derr := decodeStrict(out)
		if derr != nil {
			t.Fatalf("%s: re-encoded manifest does not decode: %v", c.Name, derr)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: round trip changed the manifest\n got: %s\nwant: %s", c.Name, out, raw)
		}
		n++
	}
	if n < 10 {
		t.Fatalf("only %d accepted cases", n)
	}
}

// TestStructCoversSchema walks the schema next to the Manifest type: every
// schema property needs a field with that JSON name and every field needs a
// schema property.
func TestStructCoversSchema(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal(schemaJSON, &schema); err != nil {
		t.Fatal(err)
	}
	defs := schema["$defs"].(map[string]any)
	var walk func(path string, s map[string]any, typ reflect.Type)
	walk = func(path string, s map[string]any, typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			typ = typ.Elem()
			if items, ok := s["items"].(map[string]any); ok {
				s = items
			}
		}
		props, _ := s["properties"].(map[string]any)
		if typ.Kind() != reflect.Struct {
			if props != nil {
				t.Errorf("%s: schema object but Go type %s", path, typ)
			}
			return
		}
		fields := map[string]reflect.StructField{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			fields[strings.Split(f.Tag.Get("json"), ",")[0]] = f
		}
		for name, p := range props {
			f, ok := fields[name]
			if !ok {
				t.Errorf("%s/%s: no struct field", path, name)
				continue
			}
			sub := p.(map[string]any)
			if ref, ok := sub["$ref"].(string); ok {
				sub = defs[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
			}
			walk(path+"/"+name, sub, f.Type)
			delete(fields, name)
		}
		for name := range fields {
			t.Errorf("%s/%s: struct field not in schema", path, name)
		}
	}
	walk("", schema, reflect.TypeOf(Manifest{}))
}

func TestDecodeTypedRejectsUnknown(t *testing.T) {
	tree := map[string]any{"schema_version": "1.0", "surprise": true}
	if _, e := decodeTyped(tree); e == nil || !e.Has(CodeDecodeFailed) {
		t.Fatalf("want DECODE_FAILED, got %v", e)
	}
}

func TestClassifyNumber(t *testing.T) {
	cases := []struct{ in, canon, code string }{
		{"0", "0", ""}, {"-0", "0", ""}, {"-0.0e-5", "0", ""}, {"0e999999999999", "0", ""},
		{"16", "16", ""}, {"16.0", "16", ""}, {"1.6e1", "16", ""}, {"1600e-2", "16", ""}, {"-12", "-12", ""},
		{"9007199254740991", "9007199254740991", ""}, {"-9007199254740991", "-9007199254740991", ""},
		{"9007199254740992", "", CodeNumberOutOfRange}, {"-9007199254740992", "", CodeNumberOutOfRange},
		{"90071992547409910e-1", "9007199254740991", ""}, {"1e15", "1000000000000000", ""},
		{"1e16", "", CodeNumberOutOfRange}, {"1e400", "", CodeNumberOutOfRange}, {"1e99999999999", "", CodeNumberOutOfRange},
		{"1.5", "", CodeNumberNotInteger}, {"1e-1", "", CodeNumberNotInteger}, {"1e-99999999999", "", CodeNumberNotInteger},
		{"10e-1", "1", ""}, {"0.1e1", "1", ""}, {"1E+2", "100", ""}, {"0.000001e6", "1", ""},
		{"1" + strings.Repeat("0", 400) + "e-400", "1", ""},
	}
	for _, c := range cases {
		canon, code := classifyNumber(c.in)
		if canon != c.canon || code != c.code {
			t.Errorf("classifyNumber(%.30q) = %q, %q; want %q, %q", c.in, canon, code, c.canon, c.code)
		}
	}
}

func TestDecodeStrict(t *testing.T) {
	cases := []struct{ in, code, ptr string }{
		{`{"a":"\u00e9\ud83d\ude00\/\b\f\n\r\t\"\\"}`, "", ""},
		{`{"a":[1,{"b":[]}],"c":{}}`, "", ""},
		{`{"a":{"b":1,"b":2}}`, CodeDuplicateKey, "/a/b"},
		{`{"a~b/c":1,"a~b\/c":2}`, CodeDuplicateKey, "/a~0b~1c"},
		{`{"a":[0,"\udbff"]}`, CodeLoneSurrogate, "/a/1"},
		{`{"a":"\ud800\u0041"}`, CodeLoneSurrogate, "/a"},
		{`{"a":"\ud800\uzzzz"}`, CodeInvalidJSON, "/a"},
		{`{"a":[1,2,]}`, CodeInvalidJSON, "/a/2"},
		{`{"a":1,}`, CodeInvalidJSON, ""},
		{`{"a" 1}`, CodeInvalidJSON, ""},
		{`{"a":tru}`, CodeInvalidJSON, "/a"},
		{`{"a":-}`, CodeInvalidJSON, "/a"},
		{`{"a":1.e1}`, CodeInvalidJSON, "/a"},
		{`{"a":"x`, CodeInvalidJSON, "/a"},
		{`{"a":"x\`, CodeInvalidJSON, "/a"},
		{`{"a":2.5}`, CodeNumberNotInteger, "/a"},
		{`{} x`, CodeTrailingData, ""},
		{`01`, CodeTrailingData, ""},
		{strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth), "", ""},
		{strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1), CodeTooDeep, strings.Repeat("/0", MaxDepth)},
		{"\xef\xbb\xbf{}", CodeInvalidJSON, ""},
		{"{\"a\":\"\xff\"}", CodeInvalidUTF8, ""},
	}
	for _, c := range cases {
		_, err := decodeStrict([]byte(c.in))
		if c.code == "" {
			if err != nil {
				t.Errorf("%.40q: unexpected %v", c.in, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%.40q: want %s, got success", c.in, c.code)
			continue
		}
		v := err.Violations[0]
		if !strings.Contains("|"+c.code+"|", "|"+v.Code+"|") || (c.ptr != "" && v.Pointer != c.ptr) {
			t.Errorf("%.40q: got %s at %q, want %s at %q", c.in, v.Code, v.Pointer, c.code, c.ptr)
		}
	}
}

func TestPointerClipping(t *testing.T) {
	long := strings.Repeat("k", 600)
	if got := pointer([]string{"a", long, "b"}); got != "/a" {
		t.Errorf("pointer = %q, want /a", got)
	}
	if got := pointer([]string{"a/b", "c~d"}); got != "/a~1b/c~0d" {
		t.Errorf("pointer = %q", got)
	}
	if got := excerpt(strings.Repeat("é", 100)); len(got) > 64*6+5 || !strings.HasSuffix(got, "...") {
		t.Errorf("excerpt = %q", got)
	}
}

func TestViolationCap(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{`)
	for i := 0; i < 300; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"x` + index(i) + `":0`)
	}
	b.WriteString(`}`)
	_, err := Parse([]byte(b.String()))
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want *Error, got %v", err)
	}
	if len(e.Violations) != MaxViolations || e.Omitted != 300+20-MaxViolations {
		t.Fatalf("got %d violations, %d omitted", len(e.Violations), e.Omitted)
	}
	if msg := e.Error(); len(msg) > 400 || !strings.Contains(msg, "320 violation") {
		t.Fatalf("Error() = %q", msg)
	}
}

func TestPathASCIIGuard(t *testing.T) {
	m := &Manifest{SchemaVersion: "1.0", Files: map[string]string{"bin/plugin": "", "bin/plügin": "", "BIN/PLUGIN": ""}, Entrypoint: "bin/plugin"}
	vs := installerRules(m)
	codes := map[string]int{}
	for _, v := range vs {
		codes[v.Code]++
	}
	if codes[CodePathNotASCII] != 1 || codes[CodePathCaseCollision] != 2 || len(vs) != 3 {
		t.Fatalf("got %+v", vs)
	}
}

func TestPathRules(t *testing.T) {
	m := &Manifest{SchemaVersion: "1.0", Files: map[string]string{
		"bin/plugin": "", "Bin": "", "a": "", "a-b/c": "", "a.d": "", "x/y": "", "x/y/z": "",
		"Signatures/manifest.sig": "", "MANIFEST.JSON": "", "signatures": "", "docs/signatures/x": "",
	}, Entrypoint: "bin/plugin"}
	got := map[string]string{}
	for _, v := range installerRules(m) {
		got[v.Pointer] += v.Code + " "
	}
	want := map[string]string{
		"/files/Bin":                      CodePathFileDirConflict + " ",
		"/files/x~1y":                     CodePathFileDirConflict + " ",
		"/files/Signatures~1manifest.sig": CodePathReserved + " ",
		"/files/MANIFEST.JSON":            CodePathReserved + " ",
		"/files/signatures":               CodePathReserved + " " + CodePathFileDirConflict + " ",
	}
	for p, w := range want {
		if got[p] != w {
			t.Errorf("%s: got %q, want %q", p, got[p], w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected violations: %v", got)
	}
}

func TestEffectiveDefaults(t *testing.T) {
	f := false
	if !(Lifecycle{}).EffectiveOverlapSafe() || (Lifecycle{OverlapSafe: &f}).EffectiveOverlapSafe() {
		t.Error("overlap_safe default must be true")
	}
	if (Operation{}).EffectivePlannable() || (UIRoute{}).EffectiveNav() {
		t.Error("plannable and nav default to false")
	}
	yes := true
	if (Operation{}).EffectiveReachability() || (Operation{Reachability: &f}).EffectiveReachability() ||
		!(Operation{Reachability: &yes}).EffectiveReachability() {
		t.Error("reachability defaults to false")
	}
	if (Resources{}).EffectiveKVMaxKB() != DefaultKVMaxKB {
		t.Error("kv_max_kb default")
	}
	a := ABI{Major: 1, MinimumMinor: 1 << 40}
	if a.CompatibleWith(1, 0) || !(ABI{Major: 1, MinimumMinor: 2}).CompatibleWith(1, 3) {
		t.Error("CompatibleWith")
	}
}

// TestEffectiveApproval covers the ADR-0010 §2 derivation: the declared level
// wins, and an operation without one derives it from its effect.
func TestEffectiveApproval(t *testing.T) {
	cases := []struct {
		op   Operation
		want string
	}{
		{Operation{Effect: "read"}, ApprovalAuto},
		{Operation{Effect: "write"}, ApprovalConfirm},
		{Operation{Effect: "destructive"}, ApprovalConfirm},
		{Operation{Effect: "write", Approval: ApprovalAuto}, ApprovalAuto},
		{Operation{Effect: "read", Approval: ApprovalConfirm}, ApprovalConfirm},
		{Operation{Effect: "write", Approval: ApprovalAIConfirm}, ApprovalAIConfirm},
	}
	for _, c := range cases {
		if got := c.op.EffectiveApproval(); got != c.want {
			t.Errorf("%+v: EffectiveApproval = %q, want %q", c.op, got, c.want)
		}
	}
}

// TestApprovalRules covers the guard that runs on a Manifest built outside
// Parse: Parse itself stops at the schema stage, so these codes are only
// reachable from installerRules directly (like TestPathASCIIGuard).
func TestApprovalRules(t *testing.T) {
	m := &Manifest{SchemaVersion: "1.1", Operations: []Operation{
		{Name: "missing-summary", Approval: ApprovalConfirm},
		{Name: "unknown-level", Approval: "always"},
		{Name: "blank-summary", Approval: ApprovalAuto, ApprovalSummary: "  \t "},
		{Name: "bad-description", Approval: ApprovalAIConfirm, ApprovalSummary: "ok", ApprovalDescription: "line\r\n"},
		{Name: "long-summary", Approval: ApprovalConfirm, ApprovalSummary: strings.Repeat("a", maxApprovalSummary+1)},
		{Name: "long-description", Approval: ApprovalConfirm, ApprovalSummary: "ok",
			ApprovalDescription: strings.Repeat("a", maxApprovalDescription+1)},
		{Name: "good", Approval: ApprovalAIConfirm, ApprovalSummary: "巡检",
			ApprovalDescription: "第一行\n第二行"},
	}}
	want := map[string]string{
		"/operations/0/approval_summary":     CodeApprovalSummaryMissing,
		"/operations/1/approval":             CodeApprovalInvalid,
		"/operations/2/approval_summary":     CodeApprovalSummaryInvalid,
		"/operations/3/approval_description": CodeApprovalDescriptionInvalid,
		"/operations/4/approval_summary":     CodeApprovalSummaryInvalid,
		"/operations/5/approval_description": CodeApprovalDescriptionInvalid,
	}
	got := map[string]string{}
	for _, v := range installerRules(m) {
		got[v.Pointer] += v.Code + " "
	}
	for ptr, code := range want {
		if !strings.Contains(got[ptr], code) {
			t.Errorf("%s: got %q, want %s", ptr, got[ptr], code)
		}
	}
	for ptr := range got {
		if _, ok := want[ptr]; !ok {
			t.Errorf("unexpected violation at %s: %q", ptr, got[ptr])
		}
	}
}

func TestPermissionNamespace(t *testing.T) {
	m := &Manifest{SchemaVersion: "1.2", ID: "acme", Operations: []Operation{
		{Effect: "read", Permission: "acme:read"},
		{Effect: "write", Permission: "acme.sub:write"},
		{Effect: "write", Permission: "acmeish:write"},
		{Effect: "read", Permission: "host.nodes:read"},
	}}
	vs := permissionRules(m)
	if len(vs) != 2 || vs[0].Pointer != "/operations/2/permission" || vs[1].Pointer != "/operations/3/permission" ||
		vs[0].Code != CodePermissionNamespace || vs[1].Code != CodePermissionNamespace {
		t.Fatalf("violations = %+v", vs)
	}
	m.SchemaVersion = "1.1"
	if vs := permissionRules(m); len(vs) != 0 {
		t.Fatalf("schema 1.1 violations = %+v", vs)
	}
}

func TestPermissionEffectMismatch(t *testing.T) {
	m := &Manifest{SchemaVersion: "1.2", ID: "acme", Operations: []Operation{
		{Effect: "write", Permission: "acme:read"},
		{Effect: "destructive", Permission: "acme:export"},
		{Effect: "read", Permission: "acme:run"},
	}}
	vs := permissionRules(m)
	if len(vs) != 2 || vs[0].Code != CodePermissionEffectMismatch || vs[1].Code != CodePermissionEffectMismatch {
		t.Fatalf("violations = %+v", vs)
	}
}

func TestPermissionReservedPluginID(t *testing.T) {
	for id, reserved := range map[string]bool{"host": true, "host.users": true, "qwq": true, "qwq.core": true, "hostel": false, "acme": false} {
		m := &Manifest{SchemaVersion: "1.0", ID: id}
		if got := len(permissionRules(m)) == 1; got != reserved {
			t.Fatalf("id %q reserved = %v", id, got)
		}
	}
}

// TestSchemaMinorRules covers ADR-0018: the members added in 1.3 are refused in
// a manifest that claims an older minor, so the declared version stays honest.
func TestSchemaMinorRules(t *testing.T) {
	no := false
	m := &Manifest{
		SchemaVersion: "1.2",
		Operations:    []Operation{{Name: "a"}, {Name: "b", Reachability: &no}},
		UI:            &UI{Widgets: []UIWidget{}},
	}
	got := map[string]string{}
	for _, v := range schemaMinorRules(m) {
		got[v.Pointer] = v.Code
	}
	want := map[string]string{
		"/operations/1/reachability": CodeSchemaVersionTooLow,
		"/ui/widgets":                CodeSchemaVersionTooLow,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("schema 1.2 violations = %v, want %v", got, want)
	}
	// 1.3 allows both; a minor too large to parse is already rejected as
	// unsupported and must not be reported a second time as too low.
	for _, version := range []string{"1.3", "1.99999999999999999999"} {
		m.SchemaVersion = version
		if vs := schemaMinorRules(m); len(vs) != 0 {
			t.Fatalf("schema %s violations = %+v", version, vs)
		}
	}
	m.SchemaVersion, m.UI = "1.2", &UI{}
	m.Operations[1].Reachability = nil
	if vs := schemaMinorRules(m); len(vs) != 0 {
		t.Fatalf("a 1.2 manifest without the new members: %+v", vs)
	}
}

// TestWidgetRules covers the widget rules on a Manifest built outside Parse.
func TestWidgetRules(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.3",
		Operations: []Operation{
			{Name: "stats", Effect: "read", Mode: "invoke"},
			{Name: "scan", Effect: "read", Mode: "job"},
			{Name: "apply", Effect: "write", Mode: "invoke"},
		},
		UI: &UI{Widgets: []UIWidget{
			{ID: "ok", Operation: "stats"},
			{ID: "job", Operation: "scan"},
			{ID: "write", Operation: "apply"},
			{ID: "gone", Operation: "missing"},
			{ID: "ok", Operation: "stats"},
		}},
	}
	got := map[string]string{}
	for _, v := range widgetRules(m) {
		got[v.Pointer] += v.Code + " "
	}
	want := map[string]string{
		"/ui/widgets/1/operation": CodeUIWidgetOperationUnsuitable + " ",
		"/ui/widgets/2/operation": CodeUIWidgetOperationUnsuitable + " ",
		"/ui/widgets/3/operation": CodeUIWidgetOperationUnknown + " ",
		"/ui/widgets/4/id":        CodeUIWidgetDuplicate + " ",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("violations = %v, want %v", got, want)
	}
	if vs := widgetRules(&Manifest{SchemaVersion: "1.3"}); len(vs) != 0 {
		t.Fatalf("a manifest without ui: %+v", vs)
	}
}
