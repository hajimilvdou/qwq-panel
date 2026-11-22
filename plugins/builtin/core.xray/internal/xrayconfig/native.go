// SPDX-License-Identifier: AGPL-3.0-only

package xrayconfig

// ---- 固定原生 DTO ----------------------------------------------------------
// 仅驱动创建这些类型，不解码原生用户输入，也不透传未知字段。

type nativeConfig struct {
	Log       nativeLog        `json:"log"`
	API       nativeAPI        `json:"api"`
	Stats     struct{}         `json:"stats"`
	Policy    nativePolicy     `json:"policy"`
	Inbounds  []nativeInbound  `json:"inbounds"`
	Outbounds []nativeOutbound `json:"outbounds"`
	Routing   nativeRouting    `json:"routing"`
}

type nativeLog struct {
	Access string `json:"access"`
	Error  string `json:"error"`
	Level  string `json:"loglevel"`
}

type nativeAPI struct {
	Tag      string   `json:"tag"`
	Services []string `json:"services"`
}

type nativePolicy struct {
	Levels map[string]userPolicy `json:"levels"`
	System systemPolicy          `json:"system"`
}

type userPolicy struct {
	Uplink   bool `json:"statsUserUplink"`
	Downlink bool `json:"statsUserDownlink"`
}

type systemPolicy struct {
	Uplink   bool `json:"statsInboundUplink"`
	Downlink bool `json:"statsInboundDownlink"`
}

type nativeInbound struct {
	Tag      string        `json:"tag"`
	Listen   string        `json:"listen"`
	Port     *int          `json:"port,omitempty"`
	Protocol string        `json:"protocol"`
	Settings any           `json:"settings"`
	Stream   *nativeStream `json:"streamSettings,omitempty"`
}

type vlessSettings struct {
	Decryption string       `json:"decryption"`
	Users      []nativeUser `json:"users"`
}

type nativeUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Level int    `json:"level"`
	Flow  string `json:"flow"`
}

type nativeStream struct {
	Network  string                   `json:"network"`
	Security string                   `json:"security"`
	Reality  *nativeReality           `json:"realitySettings,omitempty"`
	TLS      *nativeTLS               `json:"tlsSettings,omitempty"`
	Hysteria *nativeHysteriaTransport `json:"hysteriaSettings,omitempty"`
}

type nativeHysteriaTransport struct {
	Version int `json:"version"`
}

type nativeTLS struct {
	ServerName       string                 `json:"serverName"`
	ALPN             []string               `json:"alpn"`
	MinVersion       string                 `json:"minVersion"`
	RejectUnknownSNI bool                   `json:"rejectUnknownSni"`
	Certificates     []nativeTLSCertificate `json:"certificates"`
}

type nativeTLSCertificate struct {
	Certificate    []string `json:"certificate"`
	Key            []string `json:"key"`
	Usage          string   `json:"usage"`
	OneTimeLoading bool     `json:"oneTimeLoading"`
}

type hysteriaSettings struct {
	Version int            `json:"version"`
	Users   []hysteriaUser `json:"users"`
}

type hysteriaUser struct {
	Auth  string `json:"auth"`
	Email string `json:"email"`
	Level int    `json:"level"`
}

type ss2022Settings struct {
	Method   string       `json:"method"`
	Password string       `json:"password"`
	Users    []ss2022User `json:"users"`
	Network  string       `json:"network"`
}

type ss2022User struct {
	Password string `json:"password"`
	Email    string `json:"email"`
	Level    int    `json:"level"`
}

type nativeReality struct {
	Target      string   `json:"target"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIDs    []string `json:"shortIds"`
}

type apiSettings struct {
	Address string `json:"address"`
	Network string `json:"network"`
}

type nativeOutbound struct {
	Tag         string                `json:"tag"`
	Protocol    string                `json:"protocol"`
	SendThrough string                `json:"sendThrough,omitempty"`
	Settings    any                   `json:"settings"`
	Stream      *nativeOutboundStream `json:"streamSettings,omitempty"`
}

type nativeOutboundStream struct {
	Sockopt *nativeSockopt `json:"sockopt,omitempty"`
}

type nativeSockopt struct {
	Mark uint32 `json:"mark,omitempty"`
}

type nativeFreedomSettings struct {
	DomainStrategy string `json:"domainStrategy,omitempty"`
}

type nativeRouting struct {
	DomainStrategy string       `json:"domainStrategy,omitempty"`
	Rules          []nativeRule `json:"rules"`
}

type nativeRule struct {
	Type        string   `json:"type"`
	InboundTags []string `json:"inboundTag,omitempty"`
	User        []string `json:"user,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}
