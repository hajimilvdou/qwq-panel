// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SupportedSchemaMinor is the highest schema_version minor ("1.N") this
// package understands. Higher minors are rejected explicitly (ARCH §5.3)
// instead of being validated against rules they may have changed. 1.1 adds the
// operation approval metadata of ADR-0010; 1.2 enforces the permission naming
// rules of ADR-0014; 1.3 adds ui.widgets and operations[].reachability
// (ADR-0018); 1.0 to 1.2 manifests stay valid.
const SupportedSchemaMinor = 3

// permissionRulesMinor is the first schema minor that enforces the permission
// namespace and effect rules (ADR-0014).
const permissionRulesMinor = 2

// widgetsMinor is the schema minor that introduced ui.widgets and
// operations[].reachability (ADR-0018). A manifest that declares an older minor
// may not use them: hosts that stop at that minor reject the members as unknown,
// so accepting them here would make schema_version say nothing about which
// hosts can load the package.
const widgetsMinor = 3

// ReadOnlyActions are the permission actions a read-only role may perform
// (ADR-0014). The host's authorizer uses this table, so an operation guarded by
// one of them is visible to every viewer: it must not change anything.
var ReadOnlyActions = map[string]bool{
	"read":     true,
	"list":     true,
	"get":      true,
	"export":   true,
	"describe": true,
	"watch":    true,
}

// reservedPluginIDRoots are the id roots of the host's own namespaces.
var reservedPluginIDRoots = []string{"host", "qwq"}

// Approval metadata limits (ADR-0010 §1).
const (
	maxApprovalSummary     = 200
	maxApprovalDescription = 2000
)

// installerRules checks what JSON Schema cannot express (ARCH §5.3). It runs
// only on schema-valid manifests. tools/manifest_check.py (installer_rules)
// implements the same rules with the same pointers and codes; keep them in
// step. The approval block is re-checked here as well: the same rules are in
// the schema, but a host that trusts a decoded Manifest must not depend on
// that, and a future schema edit must not silently drop a confirmation-card
// invariant.
func installerRules(m *Manifest) []Violation {
	var vs []Violation
	add := func(ptr, code, msg string) { vs = append(vs, Violation{ptr, code, msg}) }

	// schema_version matches ^1\.(0|[1-9][0-9]*)$, so the minor has no
	// leading zeros; a parse failure means it is huge.
	minor := strings.TrimPrefix(m.SchemaVersion, "1.")
	if n, err := strconv.ParseUint(minor, 10, 32); err != nil || n > SupportedSchemaMinor {
		add("/schema_version", CodeUnsupportedSchemaVersion,
			fmt.Sprintf("schema_version minor is above the supported 1.%d", SupportedSchemaMinor))
	}

	// files: case-insensitive duplicates. The relpath pattern only admits
	// ASCII [A-Za-z0-9._-/], so ASCII lower-casing is exactly Unicode case
	// folding here, and Unicode normalization (NFC/NFD/NFKC/NFKD) is the
	// identity on ASCII: a normalization step would be dead code. The ASCII
	// guard below keeps that argument true if the pattern is ever relaxed;
	// such a change must add real folding and normalization first.
	groups := map[string][]string{}
	for k := range m.Files {
		if !isASCII(k) {
			add(join("/files", k), CodePathNotASCII, "file path must be ASCII")
			continue
		}
		f := strings.ToLower(k)
		groups[f] = append(groups[f], k)
	}
	folded := make([]string, 0, len(groups))
	for f, g := range groups {
		folded = append(folded, f)
		sort.Strings(g)
		if len(g) < 2 {
			continue
		}
		for i, k := range g {
			other := g[0]
			if i == 0 {
				other = g[1]
			}
			add(join("/files", k), CodePathCaseCollision, "path collides with "+excerpt(other)+" after case folding")
		}
	}
	// Reserved names and file/directory conflicts are also compared after
	// case folding, so they hold on case-insensitive filesystems too.
	sort.Strings(folded)
	for f, g := range groups {
		if f == "manifest.json" || f == "signatures" || strings.HasPrefix(f, "signatures/") {
			for _, k := range g {
				add(join("/files", k), CodePathReserved, "manifest.json and signatures/ are not part of files")
			}
		}
		// The first folded key after f+"/" in sort order is a child if any is.
		i := sort.SearchStrings(folded, f+"/")
		if i < len(folded) && strings.HasPrefix(folded[i], f+"/") {
			child := groups[folded[i]][0]
			for _, k := range g {
				add(join("/files", k), CodePathFileDirConflict, "path is listed as a file but is also a directory of "+excerpt(child))
			}
		}
	}

	// Every referenced file must be listed (exact, case-sensitive match).
	type ref struct{ ptr, path string }
	refs := []ref{
		{"/entrypoint", m.Entrypoint},
		{"/icon", m.Icon},
		{"/config/schema", m.Config.Schema},
		{"/provenance/sbom", m.Provenance.SBOM},
		{"/provenance/build", m.Provenance.Build},
	}
	if m.UI != nil {
		refs = append(refs, ref{"/ui/entry", m.UI.Entry})
	}
	for i, op := range m.Operations {
		base := "/operations/" + index(i)
		refs = append(refs,
			ref{base + "/request_schema", op.RequestSchema},
			ref{base + "/response_schema", op.ResponseSchema},
			ref{base + "/docs", op.Docs})
	}
	for _, r := range refs {
		if _, ok := m.Files[r.path]; r.path != "" && !ok {
			add(r.ptr, CodeFileNotListed, "referenced file "+excerpt(r.path)+" is not listed in files")
		}
	}

	// Operations: unique names, undo targets, UI routes.
	names := map[string]bool{}
	for i, op := range m.Operations {
		if names[op.Name] {
			add("/operations/"+index(i)+"/name", CodeDuplicateOperation, "operation "+excerpt(op.Name)+" is declared more than once")
		}
		names[op.Name] = true
	}
	routes := map[string]bool{}
	if m.UI != nil {
		for i, r := range m.UI.Routes {
			if routes[r.Path] {
				add("/ui/routes/"+index(i)+"/path", CodeUIRouteDuplicate, "route "+excerpt(r.Path)+" is declared more than once")
			}
			routes[r.Path] = true
		}
	}
	declared := map[CapabilityRef]bool{}
	for _, c := range m.Capabilities {
		declared[CapabilityRef{c.Name, c.Scope}] = true
	}
	for i, op := range m.Operations {
		for j, c := range op.Capabilities {
			if !declared[c] {
				add("/operations/"+index(i)+"/capabilities/"+index(j), CodeOperationCapabilityUndeclared,
					"capability "+excerpt(c.Name+":"+c.Scope)+" is not declared in the top-level capabilities")
			}
		}
	}
	for i, op := range m.Operations {
		base := "/operations/" + index(i)
		if op.Undo != "" && !names[op.Undo] {
			add(base+"/undo", CodeUndoUnknown, "undo refers to undeclared operation "+excerpt(op.Undo))
		}
		if op.UIRoute != "" && !routes[op.UIRoute] {
			add(base+"/ui_route", CodeUIRouteUndeclared, "ui_route "+excerpt(op.UIRoute)+" is not declared in ui.routes")
		}
	}
	vs = append(vs, approvalRules(m)...)
	vs = append(vs, permissionRules(m)...)
	vs = append(vs, schemaMinorRules(m)...)
	vs = append(vs, widgetRules(m)...)
	return vs
}

// schemaMinorRules refuses the members added in schema 1.3 in a manifest that
// declares an older minor (ADR-0018). Presence is what counts, not the value:
// an older host rejects "reachability": false and "widgets": [] just the same.
// A minor too large to parse is already reported as unsupported.
func schemaMinorRules(m *Manifest) []Violation {
	_, minor, _ := strings.Cut(m.SchemaVersion, ".")
	if n, err := strconv.ParseUint(minor, 10, 32); err != nil || n >= widgetsMinor {
		return nil
	}
	var vs []Violation
	add := func(pointer, member string) {
		vs = append(vs, Violation{pointer, CodeSchemaVersionTooLow,
			fmt.Sprintf("%s needs schema_version 1.%d or later", member, widgetsMinor)})
	}
	for i, op := range m.Operations {
		if op.Reachability != nil {
			add("/operations/"+index(i)+"/reachability", "reachability")
		}
	}
	if m.UI != nil && m.UI.Widgets != nil {
		add("/ui/widgets", "ui.widgets")
	}
	return vs
}

// widgetRules checks ui.widgets (ADR-0018): ids are unique, and every widget
// names a read, mode=invoke operation of this plugin. The Web Shell polls that
// operation every few seconds on behalf of whoever has the overview open, so it
// must neither change anything nor start a job.
func widgetRules(m *Manifest) []Violation {
	if m.UI == nil {
		return nil
	}
	var vs []Violation
	add := func(pointer, code, msg string) { vs = append(vs, Violation{pointer, code, msg}) }
	ops := make(map[string]Operation, len(m.Operations))
	for _, op := range m.Operations {
		if _, dup := ops[op.Name]; !dup { // a duplicate is reported by its own rule
			ops[op.Name] = op
		}
	}
	ids := map[string]bool{}
	for i, w := range m.UI.Widgets {
		base := "/ui/widgets/" + index(i)
		if ids[w.ID] {
			add(base+"/id", CodeUIWidgetDuplicate, "widget "+excerpt(w.ID)+" is declared more than once")
		}
		ids[w.ID] = true
		op, ok := ops[w.Operation]
		switch {
		case !ok:
			add(base+"/operation", CodeUIWidgetOperationUnknown,
				"widget refers to undeclared operation "+excerpt(w.Operation))
		case op.Effect != "read" || op.Mode != "invoke":
			add(base+"/operation", CodeUIWidgetOperationUnsuitable,
				"a widget operation must have effect read and mode invoke")
		}
	}
	return vs
}

// permissionRules applies ADR-0014. The reserved plugin ids hold for every
// schema minor; the permission rules start at permissionRulesMinor because 1.0
// and 1.1 packages may already be signed, and the host's authorizer closes the
// viewer hole for those at run time.
func permissionRules(m *Manifest) []Violation {
	var vs []Violation
	add := func(pointer, code, msg string) { vs = append(vs, Violation{pointer, code, msg}) }
	for _, root := range reservedPluginIDRoots {
		if m.ID == root || strings.HasPrefix(m.ID, root+".") {
			add("/id", CodePluginIDReserved, "plugin id must not use the reserved namespace "+root)
		}
	}
	_, minor, _ := strings.Cut(m.SchemaVersion, ".")
	if n, err := strconv.ParseUint(minor, 10, 32); err != nil || n < permissionRulesMinor {
		return vs
	}
	checkNamespace := func(pointer, permission string) {
		res, _, _ := strings.Cut(permission, ":")
		if res != m.ID && !strings.HasPrefix(res, m.ID+".") {
			add(pointer, CodePermissionNamespace, "permission resource must be the plugin id or start with it")
		}
	}
	for i, op := range m.Operations {
		p := "/operations/" + index(i) + "/permission"
		checkNamespace(p, op.Permission)
		_, act, _ := strings.Cut(op.Permission, ":")
		if op.Effect != "read" && ReadOnlyActions[act] {
			add(p, CodePermissionEffectMismatch, "a read-class action cannot guard a "+excerpt(op.Effect)+" operation")
		}
	}
	if m.UI != nil {
		for i, r := range m.UI.Routes {
			checkNamespace("/ui/routes/"+index(i)+"/permission", r.Permission)
		}
	}
	return vs
}

// approvalRules re-checks the operation approval metadata of ADR-0010: the
// declared level, the summary a confirm/ai_confirm operation needs, and the
// text limits of the confirmation card. schema_version 1.0 manifests simply
// have none of these fields, so they pass.
func approvalRules(m *Manifest) []Violation {
	var vs []Violation
	add := func(ptr, code, msg string) { vs = append(vs, Violation{ptr, code, msg}) }
	for i, op := range m.Operations {
		base := "/operations/" + index(i)
		switch op.Approval {
		case "", ApprovalAuto, ApprovalConfirm, ApprovalAIConfirm:
		default:
			add(base+"/approval", CodeApprovalInvalid, "approval must be auto, confirm or ai_confirm")
		}
		if op.ApprovalSummary == "" {
			if op.Approval == ApprovalConfirm || op.Approval == ApprovalAIConfirm {
				add(base+"/approval_summary", CodeApprovalSummaryMissing,
					"approval "+op.Approval+" needs an approval_summary")
			}
		} else if strings.TrimSpace(op.ApprovalSummary) == "" ||
			!approvalTextOK(op.ApprovalSummary, false) ||
			utf8.RuneCountInString(op.ApprovalSummary) > maxApprovalSummary {
			add(base+"/approval_summary", CodeApprovalSummaryInvalid,
				"approval_summary must be one non-blank line without control or bidi characters, at most 200 characters")
		}
		if op.ApprovalDescription != "" &&
			(!approvalTextOK(op.ApprovalDescription, true) ||
				utf8.RuneCountInString(op.ApprovalDescription) > maxApprovalDescription) {
			add(base+"/approval_description", CodeApprovalDescriptionInvalid,
				"approval_description must have no control or bidi characters other than newlines, at most 2000 characters")
		}
	}
	return vs
}

// approvalTextOK reports whether s may be shown as one line (newlines=false)
// or as a multi-line block (newlines=true) of untrusted user-facing text: no C0
// or C1 controls, no DEL, no bidi overrides or isolates, and no replacement
// characters (a U+FFFD in an already validated document means the text was
// mangled somewhere).
func approvalTextOK(s string, newlines bool) bool {
	for _, r := range s {
		if newlines && r == '\n' {
			continue
		}
		if unicode.IsControl(r) || (r >= 0x202a && r <= 0x202e) ||
			(r >= 0x2066 && r <= 0x2069) || r == utf8.RuneError {
			return false
		}
	}
	return true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
