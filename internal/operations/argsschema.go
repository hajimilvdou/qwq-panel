// SPDX-License-Identifier: AGPL-3.0-only

package operations

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"regexp"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// ---------------------------------------------------------------------------
// 插件动作参数的 JSON Schema 校验（ARCH §5.4、ADR-0011 §7）
//
// 插件在 manifest 里声明 request_schema，目录把它作为 Action.ArgsSchema 带进来。
// 宿主在派发前按它校验参数：不合规的参数不会到达插件。schema 来自已验签的包，
// 但仍按不可信输入处理——禁止任何外部 $ref，编译失败一律拒绝（fail closed）。
// ---------------------------------------------------------------------------

// argsSchemaURL is the resource name every args schema is compiled under.
const argsSchemaURL = "urn:qwq:action-args"

// maxArgsViolations bounds the violations reported for one request.
const maxArgsViolations = 20

// errExternalRef refuses every $ref outside the schema document.
var errExternalRef = errors.New("external schema references are not allowed")

type denySchemaLoader struct{}

func (denySchemaLoader) Load(string) (any, error) { return nil, errExternalRef }

// argsSchemas caches compiled schemas by content digest; a plugin update with a
// new schema simply gets a new entry.
var argsSchemas sync.Map // [sha256.Size]byte -> *compiledArgsSchema

type compiledArgsSchema struct {
	schema *jsonschema.Schema
	err    error
}

func compileArgsSchema(doc []byte) (*jsonschema.Schema, error) {
	key := sha256.Sum256(doc)
	if v, ok := argsSchemas.Load(key); ok {
		c := v.(*compiledArgsSchema)
		return c.schema, c.err
	}
	c := &compiledArgsSchema{}
	c.schema, c.err = func() (*jsonschema.Schema, error) {
		v, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
		if err != nil {
			return nil, err
		}
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.UseLoader(denySchemaLoader{})
		compiler.UseRegexpEngine(func(s string) (jsonschema.Regexp, error) { return regexp.Compile(s) })
		if err := compiler.AddResource(argsSchemaURL, v); err != nil {
			return nil, err
		}
		return compiler.Compile(argsSchemaURL)
	}()
	argsSchemas.Store(key, c)
	return c.schema, c.err
}

// validateArgs checks canonical args against the action's request schema. An
// action without a schema accepts any object (host actions are validated by
// their own handlers).
func validateArgs(act Action, args []byte) error {
	if len(act.ArgsSchema) == 0 {
		return nil
	}
	schema, err := compileArgsSchema(act.ArgsSchema)
	if err != nil {
		return problem.New(problem.ValidationFailed, "The action's argument schema is not usable; nothing was dispatched.")
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(args))
	if err != nil {
		return problem.Validation(violation("/args", "INVALID_JSON", "Arguments must be a JSON object."))
	}
	err = schema.Validate(inst)
	if err == nil {
		return nil
	}
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return problem.Validation(violation("/args", "SCHEMA_VIOLATION", "The arguments do not match the action's schema."))
	}
	var out []problem.Violation
	collectArgsViolations(ve, &out)
	if len(out) == 0 {
		out = append(out, violation("/args", "SCHEMA_VIOLATION", "The arguments do not match the action's schema."))
	}
	return problem.Validation(out...)
}

// collectArgsViolations flattens the library's error tree into leaf
// violations. The message is fixed text: it never echoes the schema author's
// free text or the argument values.
func collectArgsViolations(e *jsonschema.ValidationError, out *[]problem.Violation) {
	if len(*out) >= maxArgsViolations {
		return
	}
	if len(e.Causes) > 0 {
		for _, c := range e.Causes {
			collectArgsViolations(c, out)
		}
		return
	}
	pointer := "/args"
	for _, tok := range e.InstanceLocation {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~", "~0"), "/", "~1")
		pointer += "/" + tok
	}
	*out = append(*out, violation(pointer, "SCHEMA_VIOLATION", "The value does not match the action's schema."))
}
