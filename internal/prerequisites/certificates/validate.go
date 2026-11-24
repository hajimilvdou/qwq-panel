// SPDX-License-Identifier: AGPL-3.0-only

package certificates

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/qwq-panel/qwq/internal/prerequisites/dns"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/prerequisites/names"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

func canonicalSpec(spec Spec) (Spec, error) {
	sans, err := tlsmgr.CanonicalSANs(spec.SANs)
	if err != nil {
		return Spec{}, err
	}
	if spec.Purpose != tlsmgr.ServerTLS && spec.Purpose != tlsmgr.TestServerTLS {
		return Spec{}, fault.New("CERTIFICATE_PURPOSE_INVALID", "证书用途无效")
	}
	return Spec{SANs: sans, Purpose: spec.Purpose}, nil
}

func sameSpec(a, b Spec) bool { return a.Purpose == b.Purpose && slices.Equal(a.SANs, b.SANs) }

func canonicalScope(scope IssuanceScope) (IssuanceScope, error) {
	spec, err := canonicalSpec(scope.Spec)
	if err != nil {
		return IssuanceScope{}, err
	}
	if spec.Purpose != tlsmgr.ServerTLS || (scope.CA != LetsEncrypt && scope.CA != LetsEncryptStaging) {
		return IssuanceScope{}, fault.New("CERTIFICATE_PURPOSE_INVALID", "ACME 只支持受控公开或 staging CA 的服务端证书")
	}
	switch scope.ChallengeType {
	case "", "dns-01":
		scope.ChallengeType = ""
		zone, err := names.DNS(scope.Provider.ZoneName, false)
		if err != nil || zone != scope.Provider.ZoneName || !names.ID(scope.Provider.ProviderID) || !names.ID(scope.Provider.ZoneID) || !names.ID(scope.Provider.Revision) || (scope.Provider.Kind != dns.Cloudflare && scope.Provider.Kind != dns.Aliyun) {
			return IssuanceScope{}, fault.New("SCOPE_INVALID", "证书 DNS 提供商范围无效")
		}
		for _, san := range spec.SANs {
			if !names.InZone(strings.TrimPrefix(san, "*."), zone) {
				return IssuanceScope{}, fault.New("ZONE_DENIED", "证书 SAN 超出授权 zone")
			}
		}
	case "http-01":
		if scope.Provider != (dns.Scope{}) {
			return IssuanceScope{}, fault.New("SCOPE_INVALID", "HTTP-01 模式不需要配置 DNS 提供商范围")
		}
		for _, san := range spec.SANs {
			if strings.HasPrefix(san, "*.") {
				return IssuanceScope{}, fault.New("WILDCARD_REQUIRES_DNS01", "HTTP-01 验证不支持泛域名证书，请改用 DNS-01 模式或填写精确域名")
			}
		}
	default:
		return IssuanceScope{}, fault.New("SCOPE_INVALID", "不支持的 ACME 验证模式")
	}
	scope.Spec = spec
	return scope, nil
}

// CanonicalSpec 供宿主授权复用相同 exact SAN/用途校验，不提供签发权限。
func CanonicalSpec(spec Spec) (Spec, error) { return canonicalSpec(spec) }

// CanonicalIssuance 复用固定 CA、精确 zone 与 SAN 的签发边界。
func CanonicalIssuance(scope IssuanceScope) (IssuanceScope, error) { return canonicalScope(scope) }

func validateCaller(caller Caller, write bool) error {
	if !names.ID(caller.OwnerID) || ((write || caller.PolicyID != "") && !names.ID(caller.OperationID)) || (caller.PolicyID == "") != (caller.PolicyRevision == "") || (caller.PolicyID != "" && (!names.ID(caller.PolicyID) || !names.ID(caller.PolicyRevision))) {
		return fault.New("PERMISSION_DENIED", "证书调用者或 operation 无效")
	}
	return nil
}

func validConsumerPurpose(purpose string) bool {
	switch purpose {
	case "panel.https",
		"proxy.hysteria2",
		"proxy.anytls",
		"proxy.vless",
		"proxy.vmess",
		"proxy.trojan",
		"proxy.tls",
		"ingress.https",
		"probe.https":
		return true
	default:
		return false
	}
}

func canonicalConsumer(consumer Consumer) (Consumer, error) {
	if !names.ID(consumer.PluginID) || !names.ID(consumer.ProfileID) || !names.ID(consumer.NodeID) || !validConsumerPurpose(consumer.Purpose) {
		return Consumer{}, fault.New("CONSUMER_INVALID", "证书消费者身份或用途无效")
	}
	name, err := names.DNS(consumer.SNI, false)
	if err != nil {
		return Consumer{}, fault.New("SAN_MISMATCH", "消费者需要有效 DNS SNI")
	}
	consumer.SNI = name
	return consumer, nil
}

// CanonicalConsumer 供宿主事实核对复用相同身份、SNI 与用途校验，不授予消费权限。
func CanonicalConsumer(consumer Consumer) (Consumer, error) { return canonicalConsumer(consumer) }

func fingerprint(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", fault.New("STATE_INVALID", "证书请求无法计算版本")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func key(ownerID, certificateID string) string {
	sum := sha256.Sum256([]byte(ownerID + "\x00" + certificateID))
	return "certificates/resource/" + hex.EncodeToString(sum[:])
}

func consumerKey(consumer Consumer) string {
	sum := sha256.Sum256([]byte(consumer.PluginID + "\x00" + consumer.ProfileID + "\x00" + consumer.NodeID + "\x00" + consumer.Purpose))
	return hex.EncodeToString(sum[:])
}

func validMaterialReference(reference MaterialRef) bool {
	return reference != "" && len(reference) <= 128 && names.ID(string(reference))
}
