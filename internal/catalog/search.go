// SPDX-License-Identifier: AGPL-3.0-only

package catalog

import (
	"strings"
	"unicode"
)

// Search is a small lexical index, good enough for a catalog of a few hundred
// actions: ASCII words (with prefix match), CJK character bigrams, and a short
// synonym table so that "开启防火墙" finds "enable firewall" and the reverse.
// Weights: ID tokens 3, summary 2, permission 1.

const (
	wID         = 3
	wSummary    = 2
	wPermission = 1
)

// synonyms map a query token to tokens that may appear in actions. Keep it
// short and domain specific; it exists for Chinese queries over English host
// summaries and common verbs.
var synonyms = map[string][]string{
	"enable": {"on", "start", "开启", "启用"}, "disable": {"off", "stop", "关闭", "停用"},
	"开启": {"enable", "start", "on"}, "启用": {"enable", "start"}, "打开": {"enable", "open"},
	"关闭": {"disable", "stop", "off"}, "停用": {"disable", "stop"},
	"create": {"add", "new", "创建", "新建"}, "add": {"create", "添加"},
	"创建": {"create", "add"}, "新建": {"create"}, "添加": {"add", "create"},
	"delete": {"remove", "删除"}, "remove": {"delete", "删除"}, "删除": {"delete", "remove", "uninstall"},
	"update": {"change", "edit", "修改"}, "修改": {"update", "change"}, "更改": {"update", "change"},
	"install": {"安装"}, "安装": {"install"}, "uninstall": {"卸载"}, "卸载": {"uninstall", "remove"},
	"user": {"users", "用户"}, "users": {"user", "用户"}, "用户": {"user", "users"},
	"plugin": {"plugins", "插件"}, "plugins": {"plugin", "插件"}, "插件": {"plugin", "plugins"},
	"防火": {"firewall"}, "火墙": {"firewall"}, "firewall": {"防火", "火墙"},
	"端口": {"port"}, "port": {"端口"}, "密钥": {"key", "keys"}, "key": {"密钥"},
	"密码": {"password"}, "password": {"密码"}, "登录": {"login", "ssh"},
	"监控": {"monitor", "metrics"}, "安全": {"security"}, "security": {"安全"},
	"巡检": {"scan"}, "scan": {"巡检", "扫描"}, "扫描": {"scan"}, "基线": {"baseline"}, "baseline": {"基线"},
}

// tokens splits text into lower-case ASCII words and CJK bigrams (single CJK
// characters only when the text has exactly one).
func tokens(s string) []string {
	var out []string
	var word []rune
	var cjk []rune
	flushWord := func() {
		if len(word) > 0 {
			out = append(out, string(word))
			word = word[:0]
		}
	}
	flushCJK := func() {
		switch {
		case len(cjk) == 1:
			out = append(out, string(cjk))
		case len(cjk) > 1:
			for i := 0; i+1 < len(cjk); i++ {
				out = append(out, string(cjk[i:i+2]))
			}
		}
		cjk = cjk[:0]
	}
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Han, r):
			flushWord()
			cjk = append(cjk, r)
		case r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r)):
			flushCJK()
			word = append(word, unicode.ToLower(r))
		default:
			flushWord()
			flushCJK()
		}
	}
	flushWord()
	flushCJK()
	return out
}

func tokensOf(e *Entry) []string {
	var idx []string
	add := func(prefix string, toks []string) {
		for _, t := range toks {
			idx = append(idx, prefix+t)
		}
	}
	add("i:", tokens(e.ID))
	add("s:", tokens(e.Summary))
	add("p:", tokens(e.Permission))
	return idx
}

// queryTokens returns the query's tokens, each with its synonyms.
func queryTokens(q string) [][]string {
	var out [][]string
	for _, t := range tokens(q) {
		alts := append([]string{t}, synonyms[t]...)
		out = append(out, alts)
	}
	return out
}

func score(e *Entry, q [][]string, raw string) int {
	if strings.EqualFold(strings.TrimSpace(raw), e.ID) {
		return 1000
	}
	total, matched := 0, 0
	for _, alts := range q {
		best := 0
		for _, t := range alts {
			for _, it := range e.index {
				w := weight(it[0])
				v := it[2:]
				switch {
				case v == t:
				case len(t) >= 3 && t[0] < 128 && strings.HasPrefix(v, t):
					w = max(w-1, 1) // prefix match counts a little less
				default:
					continue
				}
				best = max(best, w)
			}
		}
		if best > 0 {
			matched++
			total += best
		}
	}
	if matched == 0 {
		return 0
	}
	// Prefer actions matching more of the query.
	return total * matched * 10 / len(q)
}

func weight(field byte) int {
	switch field {
	case 'i':
		return wID
	case 's':
		return wSummary
	default:
		return wPermission
	}
}
