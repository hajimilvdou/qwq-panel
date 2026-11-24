// SPDX-License-Identifier: AGPL-3.0-only

package firewall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

type matchObject struct {
	Op    string          `json:"op"`
	Left  json.RawMessage `json:"left"`
	Right json.RawMessage `json:"right"`
}

// ======================== 闭合表达式白名单 ========================
// 只允许 TCP/UDP 目标端口、IP 来源、lo、已建立连接，以及 accept/drop。
// 不能引用命名集合、路由到其他链、改 mark/NAT 或传递任意原生表达式。
func normalizeRule(rule *ruleObject) error {
	if rule.Family != "inet" || rule.Table != "qwq" || rule.Chain != "input" || len(rule.Expr) == 0 || len(rule.Expr) > 3 || len(rule.Comment) > 128 {
		return errInvalidRuleset
	}
	for _, c := range rule.Comment {
		if unicode.IsControl(c) {
			return errInvalidRuleset
		}
	}
	for i, raw := range rule.Expr {
		object, err := singleObject(raw)
		if err != nil {
			return err
		}
		if i == len(rule.Expr)-1 {
			for action, value := range object {
				if (action != "accept" && action != "drop") || !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
					return errInvalidRuleset
				}
				rule.Expr[i] = json.RawMessage(`{"` + action + `":null}`)
			}
			continue
		}
		rawMatch, ok := object["match"]
		if !ok {
			return errInvalidRuleset
		}
		var match matchObject
		if err := decodeObject(rawMatch, &match); err != nil || match.Op != "==" {
			return errInvalidRuleset
		}
		class, err := normalizeMatch(&match)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(map[string]any{"match": match})
		if err != nil {
			return err
		}
		rule.Expr[i] = encoded
		if len(rule.Expr) == 2 {
			rule.class = class
		}
	}
	rule.Handle = 0
	return nil
}

func normalizeMatch(match *matchObject) (string, error) {
	left, err := singleObject(match.Left)
	if err != nil {
		return "", err
	}
	var canonicalLeft any
	var canonicalRight any
	var class string
	switch {
	case left["payload"] != nil:
		var payload struct {
			Protocol string `json:"protocol"`
			Field    string `json:"field"`
		}
		if decodeObject(left["payload"], &payload) != nil {
			return "", errInvalidRuleset
		}
		canonicalLeft = map[string]any{"payload": payload}
		if (payload.Protocol == "tcp" || payload.Protocol == "udp") && payload.Field == "dport" {
			canonicalRight, err = portExpression(match.Right)
			class = payload.Protocol + "-port"
		} else if (payload.Protocol == "ip" || payload.Protocol == "ip6") && payload.Field == "saddr" {
			canonicalRight, err = addressExpression(match.Right, payload.Protocol == "ip")
			class = "address"
		} else if payload.Protocol == "icmpv6" && payload.Field == "type" {
			canonicalRight, err = icmpv6TypeExpression(match.Right)
			class = "icmpv6-type"
		} else {
			return "", errInvalidRuleset
		}
	case left["meta"] != nil:
		var meta struct {
			Key string `json:"key"`
		}
		var name string
		if decodeObject(left["meta"], &meta) != nil || meta.Key != "iifname" || json.Unmarshal(match.Right, &name) != nil || name != "lo" {
			return "", errInvalidRuleset
		}
		canonicalLeft, canonicalRight, class = map[string]any{"meta": meta}, "lo", "loopback"
	case left["ct"] != nil:
		var ct struct {
			Key string `json:"key"`
		}
		if decodeObject(left["ct"], &ct) != nil || ct.Key != "state" {
			return "", errInvalidRuleset
		}
		canonicalRight, err = stateExpression(match.Right)
		canonicalLeft, class = map[string]any{"ct": ct}, "state"
	default:
		return "", errInvalidRuleset
	}
	if err != nil {
		return "", err
	}
	match.Left, err = json.Marshal(canonicalLeft)
	if err != nil {
		return "", err
	}
	match.Right, err = json.Marshal(canonicalRight)
	return class, err
}

type portRangeElem struct {
	lo uint32
	hi uint32
}

func parseSinglePortOrRangeRaw(raw []byte) (portRangeElem, error) {
	var port uint32
	if json.Unmarshal(raw, &port) == nil {
		if port == 0 || port > 65535 {
			return portRangeElem{}, errInvalidRuleset
		}
		return portRangeElem{lo: port, hi: port}, nil
	}
	var rng struct {
		Range []uint32 `json:"range"`
	}
	if decodeObject(raw, &rng) != nil || len(rng.Range) != 2 {
		return portRangeElem{}, errInvalidRuleset
	}
	lo, hi := rng.Range[0], rng.Range[1]
	if lo == 0 || hi == 0 || lo > 65535 || hi > 65535 || lo > hi {
		return portRangeElem{}, errInvalidRuleset
	}
	return portRangeElem{lo: lo, hi: hi}, nil
}

func (e portRangeElem) toJSONValue() any {
	if e.lo == e.hi {
		return e.lo
	}
	return map[string]any{"range": []uint32{e.lo, e.hi}}
}

func portExpression(raw []byte) (any, error) {
	if elem, err := parseSinglePortOrRangeRaw(raw); err == nil {
		return elem.toJSONValue(), nil
	}
	var set struct {
		Items []json.RawMessage `json:"set"`
	}
	if decodeObject(raw, &set) != nil || len(set.Items) == 0 || len(set.Items) > maxPorts {
		return nil, errInvalidRuleset
	}
	elems := make([]portRangeElem, 0, len(set.Items))
	for _, item := range set.Items {
		elem, err := parseSinglePortOrRangeRaw(item)
		if err != nil {
			return nil, errInvalidRuleset
		}
		elems = append(elems, elem)
	}
	slices.SortFunc(elems, func(a, b portRangeElem) int {
		if a.lo != b.lo {
			if a.lo < b.lo {
				return -1
			}
			return 1
		}
		if a.hi < b.hi {
			return -1
		}
		if a.hi > b.hi {
			return 1
		}
		return 0
	})
	elems = slices.Compact(elems)
	out := make([]any, 0, len(elems))
	for _, e := range elems {
		out = append(out, e.toJSONValue())
	}
	return map[string]any{"set": out}, nil
}

// ParseFirewallPortOrRange 支持单端口 "443" 与端口段 "20000-30000"（如 Hysteria2 端口跳跃）。
func ParseFirewallPortOrRange(expr string) (nftElem string, startPort, endPort uint16, err error) {
	s := strings.TrimSpace(expr)
	if idx := strings.IndexByte(s, '-'); idx > 0 {
		lo, err1 := strconv.ParseUint(strings.TrimSpace(s[:idx]), 10, 16)
		hi, err2 := strconv.ParseUint(strings.TrimSpace(s[idx+1:]), 10, 16)
		if err1 != nil || err2 != nil || lo == 0 || hi == 0 || lo > hi {
			return "", 0, 0, fmt.Errorf("非法端口范围 %q（格式示例：20000-30000）", expr)
		}
		if lo == hi {
			return strconv.FormatUint(lo, 10), uint16(lo), uint16(hi), nil
		}
		return fmt.Sprintf("%d-%d", lo, hi), uint16(lo), uint16(hi), nil
	}
	p, perr := strconv.ParseUint(s, 10, 16)
	if perr != nil || p == 0 {
		return "", 0, 0, fmt.Errorf("非法端口号 %q（范围 1~65535 或起止段 20000-30000）", expr)
	}
	return strconv.FormatUint(p, 10), uint16(p), uint16(p), nil
}

func addressExpression(raw []byte, ipv4 bool) (any, error) {
	var name string
	if json.Unmarshal(raw, &name) == nil {
		address, err := netip.ParseAddr(name)
		if err != nil || address.Zone() != "" || address.Is4() != ipv4 || address.Is4In6() {
			return nil, errInvalidRuleset
		}
		return address.String(), nil
	}
	var value struct {
		Prefix struct {
			Address string `json:"addr"`
			Length  uint32 `json:"len"`
		} `json:"prefix"`
	}
	if decodeObject(raw, &value) != nil {
		return nil, errInvalidRuleset
	}
	address, err := netip.ParseAddr(value.Prefix.Address)
	if err != nil || address.Zone() != "" || address.Is4() != ipv4 || address.Is4In6() || value.Prefix.Length > uint32(address.BitLen()) {
		return nil, errInvalidRuleset
	}
	value.Prefix.Address = netip.PrefixFrom(address, int(value.Prefix.Length)).Masked().Addr().String()
	return value, nil
}

func stateExpression(raw []byte) (any, error) {
	var value string
	if json.Unmarshal(raw, &value) == nil {
		if value != "established" && value != "related" {
			return nil, errInvalidRuleset
		}
		return value, nil
	}
	var set struct {
		Values []string `json:"set"`
	}
	if decodeObject(raw, &set) != nil || len(set.Values) == 0 || len(set.Values) > 2 {
		return nil, errInvalidRuleset
	}
	for _, value := range set.Values {
		if value != "established" && value != "related" {
			return nil, errInvalidRuleset
		}
	}
	slices.Sort(set.Values)
	return map[string]any{"set": slices.Compact(set.Values)}, nil
}

func allowedICMPv6Type(t string) bool {
	switch t {
	case "destination-unreachable", "packet-too-big", "time-exceeded",
		"parameter-problem", "echo-request", "nd-router-advert",
		"nd-neighbor-solicit", "nd-neighbor-advert":
		return true
	default:
		return false
	}
}

func icmpv6TypeExpression(raw []byte) (any, error) {
	var value string
	if json.Unmarshal(raw, &value) == nil {
		if !allowedICMPv6Type(value) {
			return nil, errInvalidRuleset
		}
		return value, nil
	}
	var set struct {
		Values []string `json:"set"`
	}
	if decodeObject(raw, &set) != nil || len(set.Values) == 0 || len(set.Values) > 8 {
		return nil, errInvalidRuleset
	}
	for _, v := range set.Values {
		if !allowedICMPv6Type(v) {
			return nil, errInvalidRuleset
		}
	}
	slices.Sort(set.Values)
	return map[string]any{"set": slices.Compact(set.Values)}, nil
}
