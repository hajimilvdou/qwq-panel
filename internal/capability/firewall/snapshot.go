// SPDX-License-Identifier: AGPL-3.0-only

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/qwq-panel/qwq/internal/capability/local"
)

type snapshot struct {
	tableExists     bool
	chainExists     bool
	definition      []byte
	persisted       []byte
	persistedExists bool
	revision        string
	pending         bool
}

func (s *Service) readSnapshot(ctx context.Context) (snapshot, error) {
	var current snapshot
	persisted, exists, err := s.State.Read()
	if err != nil {
		return current, err
	}
	if exists {
		canonical, _, err := snapshotDefinition(persisted, true)
		if err != nil {
			return current, err
		}
		current.persisted = canonical
		current.persistedExists = true
	}
	tables, err := s.execute(ctx, []string{"-j", "list", "tables"}, nil)
	if err != nil {
		return current, err
	}
	current.tableExists, err = objectExists(tables, "table", "name", "qwq")
	if err != nil {
		return current, err
	}
	if current.tableExists {
		chains, err := s.execute(ctx, []string{"-j", "list", "chains"}, nil)
		if err != nil {
			return current, err
		}
		current.chainExists, err = objectExists(chains, "chain", "name", "input")
		if err != nil {
			return current, err
		}
	}
	if current.chainExists {
		raw, err := s.execute(ctx, []string{"-j", "list", "chain", "inet", "qwq", "input"}, nil)
		if err != nil {
			return current, err
		}
		current.definition, _, err = snapshotDefinition(raw, true)
		if err != nil {
			return current, err
		}
	} else {
		objects := []nftObject{}
		if current.tableExists {
			objects = append(objects, nftObject{Table: &tableObject{Family: "inet", Name: "qwq"}})
		}
		current.definition, err = json.Marshal(nftDocument{Nftables: objects})
		if err != nil {
			return current, err
		}
	}
	current.pending = current.chainExists != current.persistedExists || (current.chainExists && !bytes.Equal(current.definition, current.persisted))
	var material bytes.Buffer
	material.Write(current.definition)
	material.WriteByte(0)
	if current.persistedExists {
		material.WriteByte(1)
	}
	material.Write(current.persisted)
	digest := sha256.Sum256(material.Bytes())
	current.revision = hex.EncodeToString(digest[:])
	return current, nil
}

func (s *Service) execute(ctx context.Context, args []string, input []byte) ([]byte, error) {
	result, err := s.Executor.Execute(ctx, local.Nft, args, input)
	if err != nil || result.ExitCode != 0 {
		clear(result.Output)
		return nil, errors.New("firewall: nft execution failed")
	}
	return result.Output, nil
}

func objectExists(raw []byte, kind, key, value string) (bool, error) {
	var document struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if decodeObject(raw, &document) != nil {
		return false, errInvalidRuleset
	}
	found := false
	for _, rawObject := range document.Nftables {
		object, err := singleObject(rawObject)
		if err != nil {
			return false, err
		}
		valueRaw, ok := object[kind]
		if !ok {
			continue
		}
		var fields map[string]json.RawMessage
		if decodeObject(valueRaw, &fields) != nil {
			return false, errInvalidRuleset
		}
		var family, name, table string
		if json.Unmarshal(fields["family"], &family) != nil || json.Unmarshal(fields[key], &name) != nil {
			return false, errInvalidRuleset
		}
		if kind == "chain" && json.Unmarshal(fields["table"], &table) != nil {
			return false, errInvalidRuleset
		}
		if family == "inet" && name == value && (kind != "chain" || table == "qwq") {
			if found {
				return false, errInvalidRuleset
			}
			found = true
		}
	}
	return found, nil
}

// snapshotDefinition 规范化真实 input 链，保留实际保护规则，不替换为期望态。
// list chain 输出可以省略 table 元素；已由独立 list tables 核验其归属。
func snapshotDefinition(raw []byte, tableExists bool) ([]byte, []uint32, error) {
	if !tableExists || len(raw) > 512<<10 {
		return nil, nil, errInvalidRuleset
	}
	var document struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if decodeObject(raw, &document) != nil || len(document.Nftables) > maxRules+6 {
		return nil, nil, errInvalidRuleset
	}
	var chain *chainObject
	var rules []ruleObject
	var ports []uint32
	for _, rawObject := range document.Nftables {
		object, err := singleObject(rawObject)
		if err != nil {
			return nil, nil, err
		}
		switch {
		case object["metainfo"] != nil:
			continue
		case object["table"] != nil:
			var table tableObject
			if decodeObject(object["table"], &table) != nil || table.Family != "inet" || table.Name != "qwq" {
				return nil, nil, errInvalidRuleset
			}
		case object["chain"] != nil:
			if chain != nil {
				return nil, nil, errInvalidRuleset
			}
			chain = new(chainObject)
			if decodeObject(object["chain"], chain) != nil || chain.Family != "inet" || chain.Table != "qwq" || chain.Name != "input" || chain.Type != "filter" || chain.Hook != "input" || chain.Priority == nil || *chain.Priority != 0 || (chain.Policy != "accept" && chain.Policy != "drop") {
				return nil, nil, errInvalidRuleset
			}
			chain.Handle = 0
		case object["rule"] != nil:
			var rule ruleObject
			if decodeObject(object["rule"], &rule) != nil || normalizeRule(&rule) != nil {
				return nil, nil, errInvalidRuleset
			}
			if rule.Comment == "qwq:preserve" {
				protected, err := preservedRulePorts(rule)
				if err != nil {
					return nil, nil, err
				}
				ports = append(ports, protected...)
			}
			rules = append(rules, rule)
		default:
			return nil, nil, errInvalidRuleset
		}
	}
	if chain == nil {
		return nil, nil, errInvalidRuleset
	}
	objects := []nftObject{{Table: &tableObject{Family: "inet", Name: "qwq"}}, {Chain: chain}}
	for _, rule := range rules {
		copy := rule
		objects = append(objects, nftObject{Rule: &copy})
	}
	definition, err := json.Marshal(nftDocument{Nftables: objects})
	return definition, ports, err
}

// preservedRulePorts 只读取已规范化的 TCP 接受保护规则，不采信注释中的端口。
func preservedRulePorts(rule ruleObject) ([]uint32, error) {
	if rule.Comment != "qwq:preserve" || !generatedGuard(rule) {
		return nil, errInvalidRuleset
	}
	var match struct {
		Match matchObject `json:"match"`
	}
	if decodeObject(rule.Expr[0], &match) != nil {
		return nil, errInvalidRuleset
	}
	var port uint32
	if json.Unmarshal(match.Match.Right, &port) == nil {
		return []uint32{port}, nil
	}
	var set struct {
		Ports []uint32 `json:"set"`
	}
	if decodeObject(match.Match.Right, &set) != nil {
		return nil, errInvalidRuleset
	}
	return set.Ports, nil
}
