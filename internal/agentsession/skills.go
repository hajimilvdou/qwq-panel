// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// Unified Skills Subsystem (parity with @deepseek-ai/dsh-skill, Codex
// .codex/skills, and OpenCode agent profiles).
//
// Skills package reusable operational workflow instructions (HOW to diagnose
// or safely change a VPS) strictly decoupled from runtime tool authorization
// (WHAT the session is allowed to execute). Activating a skill never widens
// PermissionMode or bypasses host approvals.

// SkillSpec describes one operational skill exposed in the `/` palette and
// injectable into both NativeCore and external agent turns.
type SkillSpec struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Scope        string   `json:"scope"` // builtin | user | plugin
	Category     string   `json:"category"`
	Description  string   `json:"description"`
	Instructions string   `json:"instructions,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	SourcePath   string   `json:"source_path,omitempty"`
}

// SkillRegistry manages built-in VPS operational skills plus optional
// SKILL.md files discovered from a configured directory.
type SkillRegistry struct {
	mu     sync.RWMutex
	skills map[string]SkillSpec
	order  []string
}

// NewSkillRegistry returns a registry pre-loaded with the 5 built-in qwq VPS
// operational skills matching the finalized AI workspace palette.
func NewSkillRegistry() *SkillRegistry {
	r := &SkillRegistry{skills: map[string]SkillSpec{}}
	for _, sk := range BuiltinVPSSkills() {
		r.Register(sk)
	}
	return r
}

// BuiltinVPSSkills defines the 5 core VPS operational skills.
func BuiltinVPSSkills() []SkillSpec {
	return []SkillSpec{
		{
			ID:          "proxy-audit",
			Name:        "Proxy Audit",
			Scope:       "内置 · 代理",
			Category:    "proxy",
			Description: "核对 Desired / Running 修订差异、端口放行与多端订阅同步",
			Tags:        []string{"xray", "hysteria2", "vless", "revision"},
			Instructions: "When auditing proxy state:\n" +
				"1. Read current desired vs running revision before proposing any apply.\n" +
				"2. Verify every inbound port has a matching nftables allow rule and zero conflict with existing Baota/Nginx ports.\n" +
				"3. Confirm Hysteria2 domains do not route through proxied CDN (UDP incompatible).\n" +
				"4. Present a concise diff and wait for host approval before core.apply.",
		},
		{
			ID:          "ssh-guard",
			Name:        "SSH Guard",
			Scope:       "内置 · 安全",
			Category:    "security",
			Description: "校验防锁死公钥、压制 cloud-init 覆盖并规划 6 步无损改端口",
			Tags:        []string{"ssh", "sshd", "cloud-init", "lockout"},
			Instructions: "When hardening or modifying SSH:\n" +
				"1. Inspect effective `sshd -T` and `/etc/ssh/sshd_config.d/*` precedence (especially `50-cloud-init.conf`).\n" +
				"2. Never disable password login unless at least one valid public key is verified in authorized_keys.\n" +
				"3. Any SSH port change must follow the 6-step dual-port saga: allow new port first, verify handshake, then remove old port.",
		},
		{
			ID:          "memory-slim",
			Name:        "Memory Slim",
			Scope:       "内置 · 系统",
			Category:    "system",
			Description: "剖析 1C1G cgroup 内存水位、定位大进程并安全释放 Page Cache",
			Tags:        []string{"1c1g", "memory", "cgroup", "oom"},
			Instructions: "When inspecting 1C1G host memory:\n" +
				"1. Separate RSS (qwq-host, xray, mysqld, nginx) from reclaimable Linux Page Cache.\n" +
				"2. Never kill stateful databases (mysqld/postgres) automatically; suggest safe cache drop or log rotation first.\n" +
				"3. Report exact MiB before and after any action.",
		},
		{
			ID:          "ipv6-route",
			Name:        "IPv6 Route",
			Scope:       "内置 · 路由",
			Category:    "routing",
			Description: "测试双栈两跳策略与 OpenAI / Claude 原生 IPv6 出口可达性",
			Tags:        []string{"ipv6", "dual-stack", "openai", "routing"},
			Instructions: "When troubleshooting dual-stack routing:\n" +
				"1. Distinguish Hop 1 (client ingress IPv4/IPv6) from Hop 2 (VPS egress IPv4/IPv6).\n" +
				"2. Verify AI domains (openai/claude/anthropic) bind to native IPv6 egress while CN/LAN domains stay direct.",
		},
		{
			ID:          "baota-coexist",
			Name:        "Baota Coexist",
			Scope:       "内置 · 共存",
			Category:    "coexist",
			Description: "只读识别宝塔 Nginx / UFW 存量规则，确保零端口冲突",
			Tags:        []string{"baota", "nginx", "ufw", "coexist"},
			Instructions: "When operating on a host with existing Baota/UFW:\n" +
				"1. Treat existing Nginx 80/443 and UFW tables as read-only unless explicit takeover was approved.\n" +
				"2. Keep qwq management bound to 127.0.0.1 loopback or non-conflicting TLS ports.",
		},
	}
}

// Register adds or updates a skill.
func (r *SkillRegistry) Register(sk SkillSpec) {
	if sk.ID == "" {
		return
	}
	id := strings.ToLower(strings.TrimSpace(sk.ID))
	sk.ID = id
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.skills[id]; !exists {
		r.order = append(r.order, id)
	}
	r.skills[id] = sk
}

// List returns all registered skills in stable order.
func (r *SkillRegistry) List() []SkillSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]SkillSpec, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.skills[id])
	}
	return out
}

// Get retrieves one skill by ID or case-insensitive name.
func (r *SkillRegistry) Get(idOrName string) (SkillSpec, bool) {
	key := strings.ToLower(strings.TrimSpace(idOrName))
	r.mu.RLock()
	defer r.mu.RUnlock()
	if sk, ok := r.skills[key]; ok {
		return sk, true
	}
	for _, sk := range r.skills {
		if strings.EqualFold(sk.Name, idOrName) {
			return sk, true
		}
	}
	return SkillSpec{}, false
}

// LoadDir scans <dir>/*/SKILL.md (compatible with Codex / DSH / Antigravity
// skill folders) using bounded reads and safe frontmatter parsing.
func (r *SkillRegistry) LoadDir(dir, scope string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, problem.Wrap(err)
	}
	loaded := 0
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		p := filepath.Join(dir, ent.Name(), "SKILL.md")
		data, err := os.ReadFile(p)
		if err != nil || len(data) == 0 || len(data) > 64<<10 {
			continue
		}
		sk := ParseSkillMarkdown(ent.Name(), scope, p, string(data))
		r.Register(sk)
		loaded++
	}
	return loaded, nil
}

// ParseSkillMarkdown extracts YAML frontmatter (name/description/category) and
// body instructions from a standard SKILL.md document.
func ParseSkillMarkdown(defaultID, scope, sourcePath, content string) SkillSpec {
	sk := SkillSpec{
		ID:         strings.ToLower(strings.TrimSpace(defaultID)),
		Name:       defaultID,
		Scope:      scope,
		Category:   "custom",
		SourcePath: sourcePath,
	}
	if sk.Scope == "" {
		sk.Scope = "个人"
	}
	text := strings.ReplaceAll(content, "\r\n", "\n")
	if strings.HasPrefix(text, "---\n") {
		if end := strings.Index(text[4:], "\n---"); end >= 0 {
			fm := text[4 : 4+end]
			body := strings.TrimSpace(text[4+end+4:])
			for _, line := range strings.Split(fm, "\n") {
				k, v, ok := strings.Cut(line, ":")
				if !ok {
					continue
				}
				k = strings.ToLower(strings.TrimSpace(k))
				v = strings.Trim(strings.TrimSpace(v), `"'`)
				switch k {
				case "name":
					if v != "" {
						sk.Name = v
					}
				case "description":
					sk.Description = v
				case "category":
					if v != "" {
						sk.Category = v
					}
				}
			}
			sk.Instructions = body
			return sk
		}
	}
	sk.Instructions = strings.TrimSpace(text)
	return sk
}

// BuildSkillPrompt formats active skills into a bounded system-prompt addendum
// consumed by NativeCore and bridged to Codex / OpenCode / DSH.
func (r *SkillRegistry) BuildSkillPrompt(activeIDs []string) string {
	if len(activeIDs) == 0 {
		return ""
	}
	var b strings.Builder
	written := 0
	for _, id := range activeIDs {
		sk, ok := r.Get(id)
		if !ok || sk.Instructions == "" {
			continue
		}
		if written == 0 {
			b.WriteString("\n\n## Active Operational Skills\n")
		}
		fmt.Fprintf(&b, "\n### Skill: %s (%s)\n%s\n", sk.Name, sk.ID, sk.Instructions)
		written++
	}
	return b.String()
}
