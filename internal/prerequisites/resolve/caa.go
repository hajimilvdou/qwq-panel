// SPDX-License-Identifier: AGPL-3.0-only

package resolve

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"golang.org/x/net/dns/dnsmessage"
)

// ======================== RFC8659 CAA 继承与 DNS-01 限制 ========================

const typeCAA dnsmessage.Type = 257

type caaRecord struct {
	flags      byte
	tag, value string
}
type caaAnswer struct {
	records []caaRecord
	alias   string
}

func parseCAA(data []byte) (caaRecord, error) {
	if len(data) < 3 || data[1] == 0 || int(data[1])+2 > len(data) || len(data) > 4096 {
		return caaRecord{}, fault.New("DNS_INVALID_RESPONSE", "CAA RDATA 长度无效")
	}
	tag := string(data[2 : 2+int(data[1])])
	for _, character := range tag {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') {
			return caaRecord{}, fault.New("DNS_INVALID_RESPONSE", "CAA tag 无效")
		}
	}
	value := string(data[2+int(data[1]):])
	if strings.ContainsAny(value, "\x00\r\n") {
		return caaRecord{}, fault.New("DNS_INVALID_RESPONSE", "CAA value 无效")
	}
	return caaRecord{data[0], strings.ToLower(tag), value}, nil
}

func caaRecords(message dnsmessage.Message, name string) (caaAnswer, error) {
	current := strings.TrimSuffix(name, ".") + "."
	seen := map[string]bool{}
	for range 8 {
		if seen[current] {
			return caaAnswer{}, fault.New("DNS_INVALID_RESPONSE", "CAA 别名循环")
		}
		seen[current] = true
		answer := caaAnswer{}
		for _, resource := range message.Answers {
			if strings.ToLower(resource.Header.Name.String()) != current || resource.Header.Class != dnsmessage.ClassINET {
				continue
			}
			switch resource.Header.Type {
			case typeCAA:
				body, ok := resource.Body.(*dnsmessage.UnknownResource)
				if !ok || body.Type != typeCAA {
					return caaAnswer{}, fault.New("DNS_INVALID_RESPONSE", "CAA 响应类型无效")
				}
				record, err := parseCAA(body.Data)
				if err != nil {
					return caaAnswer{}, err
				}
				answer.records = append(answer.records, record)
			case dnsmessage.TypeCNAME:
				body, ok := resource.Body.(*dnsmessage.CNAMEResource)
				if !ok {
					return caaAnswer{}, fault.New("DNS_INVALID_RESPONSE", "CAA 别名类型无效")
				}
				target, err := names.DNS(strings.TrimSuffix(strings.ToLower(body.CNAME.String()), "."), false)
				if err != nil {
					return caaAnswer{}, fault.New("DNS_INVALID_RESPONSE", "CAA 别名目标无效")
				}
				if answer.alias != "" && answer.alias != target {
					return caaAnswer{}, fault.New("DNS_INVALID_RESPONSE", "CAA 别名目标不唯一")
				}
				answer.alias = target
			}
		}
		if len(answer.records) > 32 || (len(answer.records) > 0 && answer.alias != "") {
			return caaAnswer{}, fault.New("DNS_INVALID_RESPONSE", "CAA RRset 无效")
		}
		if len(answer.records) > 0 {
			slices.SortFunc(answer.records, func(a, b caaRecord) int {
				if a.flags != b.flags {
					return int(a.flags) - int(b.flags)
				}
				if a.tag != b.tag {
					return strings.Compare(a.tag, b.tag)
				}
				return strings.Compare(a.value, b.value)
			})
			answer.records = slices.Compact(answer.records)
			return answer, nil
		}
		if answer.alias == "" {
			if current != strings.TrimSuffix(name, ".")+"." {
				answer.alias = strings.TrimSuffix(current, ".")
			}
			return answer, nil
		}
		current = answer.alias + "."
	}
	return caaAnswer{}, fault.New("RESOURCE_EXHAUSTED", "CAA 别名超过查询上限")
}

func (r *Resolver) lookupCAA(ctx context.Context, name string) (caaAnswer, error) {
	var selected caaAnswer
	for index, server := range r.recursive {
		message, err := r.query(ctx, server, name, typeCAA, true)
		if err != nil {
			return caaAnswer{}, err
		}
		answer, err := caaRecords(message, name)
		if err != nil {
			return caaAnswer{}, err
		}
		if index > 0 && (selected.alias != answer.alias || !slices.Equal(selected.records, answer.records)) {
			return caaAnswer{}, fault.New("DNS_NOT_PROPAGATED", "递归 DNS 的 CAA 结果不一致")
		}
		selected = answer
	}
	return selected, nil
}

func issueAllowed(records []caaRecord, wildcard bool, accountURI string) bool {
	issuewild := slices.ContainsFunc(records, func(record caaRecord) bool { return record.tag == "issuewild" })
	tag := "issue"
	if wildcard && issuewild {
		tag = "issuewild"
	}
	present, allowed := false, false
	for _, record := range records {
		if record.flags&128 != 0 && record.tag != "issue" && record.tag != "issuewild" && record.tag != "iodef" {
			return false
		}
		if record.tag != tag {
			continue
		}
		present = true
		parts := strings.Split(record.value, ";")
		if !strings.EqualFold(strings.TrimSpace(parts[0]), "letsencrypt.org") {
			continue
		}
		match := true
		for _, parameter := range parts[1:] {
			parameter = strings.TrimSpace(parameter)
			if parameter == "" {
				continue
			}
			name, value, ok := strings.Cut(parameter, "=")
			if !ok {
				match = false
				break
			}
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "accounturi":
				match = match && strings.TrimSpace(value) == accountURI && accountURI != ""
			case "validationmethods":
				methods := strings.Split(strings.ToLower(value), ",")
				valid := false
				for _, method := range methods {
					valid = valid || strings.TrimSpace(method) == "dns-01"
				}
				match = match && valid
			default:
				match = false
			}
		}
		allowed = allowed || match
	}
	return !present || allowed
}

// CheckCAA 固定 Let's Encrypt 与 DNS-01；不允许请求注入 issuer 或校验方法。
// RFC8659 仅沿原名称的父级攀升，CNAME 目标的父级策略不移植给客户域名。
func (r *Resolver) CheckCAA(ctx context.Context, scope dns.Scope, sans []string, accountURI string) error {
	if dns.ValidateScope(scope) != nil || len(sans) == 0 || len(sans) > 64 {
		return fault.New("SCOPE_INVALID", "CAA 证书范围无效")
	}
	bounded, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	ctx = bounded
	cache := map[string][]caaRecord{}
	queries := 0
	for _, san := range sans {
		canonical, err := names.SAN(san)
		if err != nil || canonical != san || !names.InZone(san, scope.ZoneName) {
			return fault.New("SAN_INVALID", "CAA SAN 不在授权 zone 内")
		}
		original := strings.TrimPrefix(san, "*.")
		domain := original
		found := false
		for parents := 0; domain != "" && parents < 128; parents++ {
			records, cached := cache[domain]
			if !cached {
				current := domain
				seen := map[string]bool{}
				for aliases := 0; aliases < 8; aliases++ {
					if seen[current] || len(cache)+len(seen) > 256 {
						return fault.New("RESOURCE_EXHAUSTED", "CAA 查询预算耗尽")
					}
					seen[current] = true
					queries += len(r.recursive)
					if queries > 256 {
						return fault.New("RESOURCE_EXHAUSTED", "CAA 总查询次数超过上限")
					}
					answer, err := r.lookupCAA(ctx, current)
					if err != nil {
						return err
					}
					if len(answer.records) > 0 || answer.alias == "" {
						records = answer.records
						break
					}
					current = answer.alias
					if aliases == 7 {
						return fault.New("RESOURCE_EXHAUSTED", "CAA 别名查询超过上限")
					}
				}
				cache[domain] = records
			}
			if len(records) > 0 {
				if !issueAllowed(records, strings.HasPrefix(san, "*."), accountURI) {
					return fault.New("CAA_FORBIDDEN", "CAA 未授权 Let's Encrypt 的 DNS-01 签发")
				}
				found = true
				break
			}
			_, parent, ok := strings.Cut(domain, ".")
			if !ok {
				domain = ""
			} else {
				domain = parent
			}
		}
		if !found && domain != "" {
			return fault.New("RESOURCE_EXHAUSTED", "CAA 继承查询超过上限")
		}
	}
	return nil
}
