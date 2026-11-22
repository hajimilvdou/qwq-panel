// SPDX-License-Identifier: AGPL-3.0-only

// Package firewall 只管理 inet qwq 的 input 链；其他能力的封禁集合独立保留。
package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

const (
	MaxRulesetBytes = 256 << 10
	maxRules        = 256
	maxPorts        = 128
)

var errInvalidRuleset = errors.New("firewall: ruleset is outside the supported safe subset")

type tableObject struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	Handle uint64 `json:"handle,omitempty"`
}
type chainObject struct {
	Family   string `json:"family"`
	Table    string `json:"table"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Hook     string `json:"hook"`
	Priority *int   `json:"prio"`
	Policy   string `json:"policy"`
	Handle   uint64 `json:"handle,omitempty"`
}
type ruleObject struct {
	Family  string            `json:"family"`
	Table   string            `json:"table"`
	Chain   string            `json:"chain"`
	Expr    []json.RawMessage `json:"expr"`
	Comment string            `json:"comment,omitempty"`
	Handle  uint64            `json:"handle,omitempty"`
	class   string
}
type nftObject struct {
	Table *tableObject `json:"table,omitempty"`
	Chain *chainObject `json:"chain,omitempty"`
	Rule  *ruleObject  `json:"rule,omitempty"`
}
type nftDocument struct {
	Nftables []nftObject `json:"nftables"`
}

// Ruleset 是已经过闭合白名单校验的规则集。原生命令只能由该类型生成。
type Ruleset struct {
	policy string
	ports  []uint32
	rules  []ruleObject
}

// Normalize 校验 nft list table 形态，拒绝所有命令、其他表/链及未知表达式。
// required 来自宿主事实，declared 仅可扩大保留端口集合；两者都不能为空。
func Normalize(raw []byte, required, declared []uint32) (*Ruleset, error) {
	if len(raw) == 0 || len(raw) > MaxRulesetBytes {
		return nil, errInvalidRuleset
	}
	ports, err := preservedPorts(required, declared)
	if err != nil {
		return nil, err
	}
	var document struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if err := decodeObject(raw, &document); err != nil || len(document.Nftables) > maxRules+6 {
		return nil, errInvalidRuleset
	}
	r := &Ruleset{ports: ports}
	var hasTable, hasChain, hasMeta bool
	for _, rawObject := range document.Nftables {
		object, err := singleObject(rawObject)
		if err != nil {
			return nil, err
		}
		switch {
		case object["metainfo"] != nil:
			var info struct {
				Version     string `json:"version"`
				ReleaseName string `json:"release_name"`
				Schema      int    `json:"json_schema_version"`
			}
			if hasMeta || decodeObject(object["metainfo"], &info) != nil || info.Schema != 1 || len(info.Version) > 96 || len(info.ReleaseName) > 96 {
				return nil, errInvalidRuleset
			}
			hasMeta = true
		case object["table"] != nil:
			var table tableObject
			if hasTable || decodeObject(object["table"], &table) != nil || table.Family != "inet" || table.Name != "qwq" {
				return nil, errInvalidRuleset
			}
			hasTable = true
		case object["chain"] != nil:
			var chain chainObject
			if hasChain || decodeObject(object["chain"], &chain) != nil || chain.Family != "inet" || chain.Table != "qwq" || chain.Name != "input" || chain.Type != "filter" || chain.Hook != "input" || chain.Priority == nil || *chain.Priority != 0 || (chain.Policy != "accept" && chain.Policy != "drop") {
				return nil, errInvalidRuleset
			}
			r.policy, hasChain = chain.Policy, true
		case object["rule"] != nil:
			var rule ruleObject
			if decodeObject(object["rule"], &rule) != nil || normalizeRule(&rule) != nil {
				return nil, errInvalidRuleset
			}
			if strings.HasPrefix(rule.Comment, "qwq:") {
				if !generatedGuard(rule) {
					return nil, errInvalidRuleset
				}
				continue
			}
			if len(r.rules) >= maxRules {
				return nil, errInvalidRuleset
			}
			r.rules = append(r.rules, rule)
		default:
			return nil, errInvalidRuleset
		}
	}
	if !hasTable || !hasChain {
		return nil, errInvalidRuleset
	}
	definition, err := r.Definition()
	if err != nil || len(definition) > MaxRulesetBytes {
		return nil, errInvalidRuleset
	}
	return r, nil
}

// Minimal 生成重置策略：只恢复 input 链的 accept 策略和三条强制保护。
func Minimal(required []uint32) (*Ruleset, error) {
	ports, err := preservedPorts(required, required)
	if err != nil {
		return nil, err
	}
	return &Ruleset{policy: "accept", ports: ports}, nil
}

func preservedPorts(required, declared []uint32) ([]uint32, error) {
	if len(required) == 0 || len(required) > maxPorts || len(declared) == 0 || len(declared) > maxPorts {
		return nil, errInvalidRuleset
	}
	ports := append([]uint32(nil), declared...)
	slices.Sort(ports)
	ports = slices.Compact(ports)
	for _, port := range append(append([]uint32(nil), required...), ports...) {
		if port == 0 || port > 65535 {
			return nil, errInvalidRuleset
		}
	}
	for _, port := range required {
		if !slices.Contains(ports, port) {
			return nil, errInvalidRuleset
		}
	}
	return ports, nil
}

func decodeObject(raw []byte, dst any) error {
	return sandbox.DecodeHelperDocument(raw, dst)
}
func singleObject(raw []byte) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := decodeObject(raw, &object); err != nil || len(object) != 1 {
		return nil, errInvalidRuleset
	}
	return object, nil
}

func generatedGuard(rule ruleObject) bool {
	if len(rule.Expr) != 2 || !bytes.Equal(rule.Expr[1], []byte(`{"accept":null}`)) {
		return false
	}
	classes := map[string]string{"qwq:preserve": "tcp-port", "qwq:loopback": "loopback", "qwq:established": "state"}
	return classes[rule.Comment] != "" && classes[rule.Comment] == rule.class
}

// Definition 返回稳定的 nft 输出形态；运行时 handle 不会进入持久配置。
func (r *Ruleset) Definition() ([]byte, error) {
	if r == nil || len(r.ports) == 0 {
		return nil, errInvalidRuleset
	}
	zero := 0
	objects := []nftObject{{Table: &tableObject{Family: "inet", Name: "qwq"}}, {Chain: &chainObject{Family: "inet", Table: "qwq", Name: "input", Type: "filter", Hook: "input", Priority: &zero, Policy: r.policy}}}
	guards, err := guardRules(r.ports)
	if err != nil {
		return nil, err
	}
	for _, rule := range append(guards, r.rules...) {
		copy := rule
		objects = append(objects, nftObject{Rule: &copy})
	}
	return json.Marshal(nftDocument{Nftables: objects})
}

// Transaction 原子替换唯一的 input 链，保留同表中的 ban 链/集合。
// 表/链是否存在取自 helper 在跨进程锁内读取的真实状态。
func (r *Ruleset) Transaction(tableExists, chainExists bool) ([]byte, error) {
	if chainExists && !tableExists {
		return nil, errInvalidRuleset
	}
	definition, err := r.Definition()
	if err != nil {
		return nil, err
	}
	var doc nftDocument
	if err := json.Unmarshal(definition, &doc); err != nil {
		return nil, err
	}
	commands := make([]any, 0, len(doc.Nftables)+1)
	if !tableExists {
		commands = append(commands, map[string]any{"add": doc.Nftables[0]})
	}
	if chainExists {
		// 只使用名称定位，不接受请求中的 handle/index；不会删除整个 qwq 表。
		commands = append(commands, map[string]any{"delete": map[string]any{"chain": struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
		}{"inet", "qwq", "input"}}})
	}
	for _, object := range doc.Nftables[1:] {
		commands = append(commands, map[string]any{"add": object})
	}
	return json.Marshal(struct {
		Nftables []any `json:"nftables"`
	}{commands})
}

func guardRules(ports []uint32) ([]ruleObject, error) {
	matches := []string{
		fmt.Sprintf(`{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":%s}}}`, mustPortsJSON(ports)),
		`{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lo"}}`,
		`{"match":{"op":"==","left":{"ct":{"key":"state"}},"right":{"set":["established","related"]}}}`,
	}
	names := []string{"qwq:preserve", "qwq:loopback", "qwq:established"}
	rules := make([]ruleObject, 0, 3)
	for i, match := range matches {
		rule := ruleObject{Family: "inet", Table: "qwq", Chain: "input", Comment: names[i], Expr: []json.RawMessage{[]byte(match), []byte(`{"accept":null}`)}}
		if err := normalizeRule(&rule); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func mustPortsJSON(ports []uint32) string {
	// uint32 数组不含可失败的 JSON 成员；仍处理错误，避免把非法 JSON 交给 nft。
	raw, err := json.Marshal(ports)
	if err != nil {
		return "[]"
	}
	return string(raw)
}
