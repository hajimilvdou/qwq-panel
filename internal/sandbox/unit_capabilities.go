// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import "strings"

// SandboxRelaxations is strictly derived by the host from the verified manifest
// capabilities (a plugin can never request systemd directives directly).
type SandboxRelaxations struct {
	// HostNetwork allows using the host network namespace and AF_INET/AF_INET6 sockets.
	// Triggered by: network.proxy(direct) | network.egress(*) | network.listen(*)
	HostNetwork bool `json:"host_network,omitempty"`

	// BindPrivilegedPorts grants only CAP_NET_BIND_SERVICE so a non-root DynamicUser
	// plugin can bind ports 80/443 without any other root capability.
	// Triggered by: network.listen(ingress | custom-domain) or verified official proxy core.
	BindPrivilegedPorts bool `json:"bind_privileged_ports,omitempty"`
}

// CapabilityRef is a lightweight projection of manifest.Capability to avoid import cycles.
type CapabilityRef struct {
	Name  string
	Scope string
}

// DeriveSandboxRelaxations derives the minimal required sandbox relaxations from
// Ed25519-verified plugin capabilities.
func DeriveSandboxRelaxations(caps []CapabilityRef) SandboxRelaxations {
	var out SandboxRelaxations
	for _, c := range caps {
		switch {
		case c.Name == "network.proxy" && c.Scope == "direct":
			out.HostNetwork = true
		case c.Name == "network.egress" && c.Scope != "":
			out.HostNetwork = true
		case c.Name == "network.listen" && c.Scope != "":
			out.HostNetwork = true
			if c.Scope == "ingress" || c.Scope == "custom-domain" {
				out.BindPrivilegedPorts = true
			}
		}
	}
	return out
}

// ApplySandboxRelaxations rewrites only the permitted sandbox directives in the
// rendered service unit, keeping all other 25+ systemd hardening lines intact.
func ApplySandboxRelaxations(unitText string, rel SandboxRelaxations) (string, error) {
	out := unitText
	var err error
	if rel.HostNetwork {
		if out, err = replaceSingleDirective(out, "PrivateNetwork=", "PrivateNetwork=no"); err != nil {
			return "", err
		}
		if out, err = replaceSingleDirective(out, "RestrictAddressFamilies=", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"); err != nil {
			return "", err
		}
	}
	if rel.BindPrivilegedPorts {
		if out, err = replaceSingleDirective(out, "CapabilityBoundingSet=", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE"); err != nil {
			return "", err
		}
		if out, err = replaceSingleDirective(out, "AmbientCapabilities=", "AmbientCapabilities=CAP_NET_BIND_SERVICE"); err != nil {
			return "", err
		}
	}
	return out, nil
}

func replaceSingleDirective(text, prefix, replacement string) (string, error) {
	lines := strings.Split(text, "\n")
	found := 0
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) {
			lines[i] = replacement
			found++
		}
	}
	if found != 1 {
		return "", &directiveMatchError{prefix: prefix, count: found}
	}
	return strings.Join(lines, "\n"), nil
}

type directiveMatchError struct {
	prefix string
	count  int
}

func (e *directiveMatchError) Error() string {
	return "sandbox: directive " + e.prefix + " did not match uniquely"
}
