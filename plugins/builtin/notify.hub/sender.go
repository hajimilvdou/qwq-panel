// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// NotifyEvent 是需要投递的结构化告警/通知事件。
type NotifyEvent struct {
	EventID   string            `json:"event_id"`
	Source    string            `json:"source"`
	Severity  string            `json:"severity"` // info | warn | critical
	Title     string            `json:"title"`
	Message   string            `json:"message"`
	DedupKey  string            `json:"dedup_key,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// SendOutcome 记录一次通道投递结果。
type SendOutcome struct {
	HTTPStatus int
	Err        error
}

// newSafeHTTPClient 构造默认防 SSRF 的外发客户端（拒绝回环、内网、链路本地与重定向）。
func newSafeHTTPClient(allowPrivate bool, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        8,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				ip = ip.Unmap()
				if isAlwaysBlockedMetadataIP(ip) {
					return nil, fmt.Errorf("egress blocked to cloud metadata or link-local address %s", ip)
				}
				if !allowPrivate && isDisallowedIP(ip) {
					return nil, fmt.Errorf("egress blocked to private or loopback address %s", ip)
				}
			}
			for _, ip := range ips {
				conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
				if derr == nil {
					return conn, nil
				}
				err = derr
			}
			return nil, err
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

var (
	notifyCGNATPrefix       = netip.MustParsePrefix("100.64.0.0/10")
	alwaysBlockedMetadataV4 = []netip.Prefix{
		netip.MustParsePrefix("169.254.0.0/16"),     // AWS/GCP/Azure/DigitalOcean IMDS & IPv4 link-local
		netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud metadata
	}
	alwaysBlockedMetadataV6 = []netip.Prefix{
		netip.MustParsePrefix("fe80::/10"),         // IPv6 link-local
		netip.MustParsePrefix("fd00:ec2::254/128"), // AWS IMDSv2 IPv6
	}
)

// isAlwaysBlockedMetadataIP 即使开启 allowPrivate（允许企业内网 Webhook/SMTP），
// 也始终硬性拒绝云厂商元数据与链路本地地址，防止 SSRF 窃取实例元数据凭据。
func isAlwaysBlockedMetadataIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	u := ip.Unmap()
	if u.IsLinkLocalUnicast() || u.IsLinkLocalMulticast() {
		return true
	}
	if u.Is4() {
		for _, p := range alwaysBlockedMetadataV4 {
			if p.Contains(u) {
				return true
			}
		}
		return false
	}
	for _, p := range alwaysBlockedMetadataV6 {
		if p.Contains(u) {
			return true
		}
	}
	return false
}

func isDisallowedIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	u := ip.Unmap()
	return isAlwaysBlockedMetadataIP(u) || u.IsLoopback() || u.IsPrivate() ||
		u.IsMulticast() || u.IsUnspecified() ||
		notifyCGNATPrefix.Contains(u)
}

func validateChannelConfig(kind string, cfg ChannelConfig) error {
	switch kind {
	case "telegram":
		if strings.TrimSpace(cfg.BotToken) == "" || strings.TrimSpace(cfg.ChatID) == "" {
			return errors.New("telegram channel requires bot_token and chat_id")
		}
		if cfg.APIBase != "" {
			if err := validateHTTPURL(cfg.APIBase); err != nil {
				return fmt.Errorf("invalid api_base: %w", err)
			}
		}
	case "feishu", "dingtalk", "wecom", "discord", "webhook":
		if err := validateHTTPURL(cfg.WebhookURL); err != nil {
			return fmt.Errorf("invalid webhook_url: %w", err)
		}
		for k, v := range cfg.Headers {
			if strings.ContainsAny(k+v, "\r\n\x00") {
				return errors.New("header contains forbidden control characters")
			}
		}
	case "smtp":
		if strings.TrimSpace(cfg.SMTPHost) == "" || cfg.SMTPPort <= 0 || cfg.SMTPPort > 65535 {
			return errors.New("smtp channel requires valid smtp_host and smtp_port")
		}
		if strings.TrimSpace(cfg.SMTPFrom) == "" || len(cfg.SMTPTo) == 0 {
			return errors.New("smtp channel requires smtp_from and at least one smtp_to")
		}
		for _, field := range append([]string{cfg.SMTPHost, cfg.SMTPFrom, cfg.SMTPUser}, cfg.SMTPTo...) {
			if strings.ContainsAny(field, "\r\n\x00") {
				return errors.New("smtp field contains forbidden control characters")
			}
		}
	default:
		return fmt.Errorf("unsupported channel kind %q", kind)
	}
	return nil
}

func validateHTTPURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return errors.New("must be a valid http(s) URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("only http and https schemes are allowed")
	}
	return nil
}

func dispatchChannel(ctx context.Context, client *http.Client, allowPrivate bool, ch channelWithSecret, ev NotifyEvent) SendOutcome {
	var out SendOutcome
	switch ch.Kind {
	case "telegram":
		out = sendTelegram(ctx, client, ch.Config, ev)
	case "feishu":
		out = sendFeishu(ctx, client, ch.Config, ev)
	case "dingtalk":
		out = sendDingTalk(ctx, client, ch.Config, ev)
	case "wecom":
		out = sendWeCom(ctx, client, ch.Config, ev)
	case "discord":
		out = sendDiscord(ctx, client, ch.Config, ev)
	case "webhook":
		out = sendCustomWebhook(ctx, client, ch.Config, ev)
	case "smtp":
		timeout := 12 * time.Second
		if client != nil && client.Timeout > 0 {
			timeout = client.Timeout
		}
		out = sendSMTP(ctx, allowPrivate, timeout, ch.Config, ev)
	default:
		out = SendOutcome{Err: fmt.Errorf("unknown channel kind %q", ch.Kind)}
	}
	if out.Err != nil {
		out.Err = sanitizeDeliveryError(out.Err, ch.Config)
	}
	return out
}

// sanitizeDeliveryError 剥离 *url.Error 中的完整 URL 路径/查询串并擦除通道密钥，防止凭据泄漏进审计表与 UI。
func sanitizeDeliveryError(err error, cfg ChannelConfig) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		redacted := redactURL(ue.URL)
		if redacted == "" {
			redacted = "[redacted-url]"
		}
		msg = fmt.Sprintf("%s %s: %v", ue.Op, redacted, ue.Err)
	}
	for _, secret := range []string{cfg.BotToken, cfg.WebhookURL, cfg.Secret, cfg.SMTPPass} {
		if len(secret) >= 4 {
			msg = strings.ReplaceAll(msg, secret, "[REDACTED]")
		}
	}
	return errors.New(msg)
}

func severityBadge(sev string) string {
	switch sev {
	case "critical":
		return "[CRITICAL]"
	case "warn":
		return "[WARN]"
	default:
		return "[INFO]"
	}
}

func formatPlainText(ev NotifyEvent) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", severityBadge(ev.Severity), ev.Title)
	fmt.Fprintf(&b, "来源: %s | 时间: %s\n", ev.Source, ev.Timestamp.UTC().Format(time.RFC3339))
	if ev.Message != "" {
		b.WriteString("\n")
		b.WriteString(ev.Message)
	}
	return b.String()
}

func postJSON(ctx context.Context, client *http.Client, targetURL string, payload any, headers map[string]string) SendOutcome {
	raw, err := json.Marshal(payload)
	if err != nil {
		return SendOutcome{Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(raw))
	if err != nil {
		return SendOutcome{Err: err}
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "qwq-notify-hub/0.1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return SendOutcome{Err: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return SendOutcome{
			HTTPStatus: resp.StatusCode,
			Err:        fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(body))),
		}
	}
	return SendOutcome{HTTPStatus: resp.StatusCode}
}

func sendTelegram(ctx context.Context, client *http.Client, cfg ChannelConfig, ev NotifyEvent) SendOutcome {
	base := strings.TrimRight(cfg.APIBase, "/")
	if base == "" {
		base = "https://api.telegram.org"
	}
	endpoint := base + "/bot" + cfg.BotToken + "/sendMessage"
	payload := map[string]any{
		"chat_id":                  cfg.ChatID,
		"text":                     formatPlainText(ev),
		"disable_web_page_preview": true,
	}
	if cfg.ThreadID != "" {
		if tid, err := strconv.Atoi(cfg.ThreadID); err == nil {
			payload["message_thread_id"] = tid
		}
	}
	return postJSON(ctx, client, endpoint, payload, nil)
}

func sendFeishu(ctx context.Context, client *http.Client, cfg ChannelConfig, ev NotifyEvent) SendOutcome {
	payload := map[string]any{
		"msg_type": "text",
		"content": map[string]string{
			"text": formatPlainText(ev),
		},
	}
	if cfg.Secret != "" {
		ts := strconv.FormatInt(ev.Timestamp.Unix(), 10)
		mac := hmac.New(sha256.New, []byte(ts+"\n"+cfg.Secret))
		payload["timestamp"] = ts
		payload["sign"] = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	}
	return postJSON(ctx, client, cfg.WebhookURL, payload, nil)
}

func sendDingTalk(ctx context.Context, client *http.Client, cfg ChannelConfig, ev NotifyEvent) SendOutcome {
	target := cfg.WebhookURL
	if cfg.Secret != "" {
		ts := strconv.FormatInt(ev.Timestamp.UnixMilli(), 10)
		mac := hmac.New(sha256.New, []byte(cfg.Secret))
		_, _ = mac.Write([]byte(ts + "\n" + cfg.Secret))
		sig := url.QueryEscape(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		target = target + sep + "timestamp=" + ts + "&sign=" + sig
	}
	payload := map[string]any{
		"msgtype": "text",
		"text": map[string]string{
			"content": formatPlainText(ev),
		},
	}
	return postJSON(ctx, client, target, payload, nil)
}

func sendWeCom(ctx context.Context, client *http.Client, cfg ChannelConfig, ev NotifyEvent) SendOutcome {
	payload := map[string]any{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"content": fmt.Sprintf("### %s %s\n> 来源：`%s`\n\n%s", severityBadge(ev.Severity), ev.Title, ev.Source, ev.Message),
		},
	}
	return postJSON(ctx, client, cfg.WebhookURL, payload, nil)
}

func sendDiscord(ctx context.Context, client *http.Client, cfg ChannelConfig, ev NotifyEvent) SendOutcome {
	color := 0x1e9c8b
	if ev.Severity == "warn" {
		color = 0xd99422
	} else if ev.Severity == "critical" {
		color = 0xb5352b
	}
	payload := map[string]any{
		"embeds": []map[string]any{{
			"title":       severityBadge(ev.Severity) + " " + ev.Title,
			"description": ev.Message,
			"color":       color,
			"footer":      map[string]string{"text": "qwq notify.hub · " + ev.Source},
			"timestamp":   ev.Timestamp.UTC().Format(time.RFC3339),
		}},
	}
	return postJSON(ctx, client, cfg.WebhookURL, payload, nil)
}

func sendCustomWebhook(ctx context.Context, client *http.Client, cfg ChannelConfig, ev NotifyEvent) SendOutcome {
	body, err := json.Marshal(ev)
	if err != nil {
		return SendOutcome{Err: err}
	}
	headers := map[string]string{}
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	ts := strconv.FormatInt(ev.Timestamp.Unix(), 10)
	headers["X-QWQ-Notify-Timestamp"] = ts
	if cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(cfg.Secret))
		_, _ = mac.Write([]byte(ts + "."))
		_, _ = mac.Write(body)
		headers["X-QWQ-Notify-Signature"] = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return SendOutcome{Err: err}
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return SendOutcome{Err: err}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return SendOutcome{
			HTTPStatus: resp.StatusCode,
			Err:        fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody))),
		}
	}
	return SendOutcome{HTTPStatus: resp.StatusCode}
}

// encodeRFC2047Subject 对含非 ASCII 字符的邮件标题执行 RFC 2047 UTF-8 Base64 编码，防止中文乱码。
func encodeRFC2047Subject(raw string) string {
	clean := strings.NewReplacer("\r", "", "\n", " ").Replace(raw)
	return "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(clean)) + "?="
}

func sendSMTP(ctx context.Context, allowPrivate bool, timeout time.Duration, cfg ChannelConfig, ev NotifyEvent) SendOutcome {
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", cfg.SMTPHost)
	if err != nil {
		return SendOutcome{Err: err}
	}
	if len(ips) == 0 {
		return SendOutcome{Err: errors.New("smtp host resolved to no addresses")}
	}
	verifiedIPs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		u := ip.Unmap()
		if isAlwaysBlockedMetadataIP(u) {
			return SendOutcome{Err: fmt.Errorf("smtp egress blocked to cloud metadata or link-local address %s", u)}
		}
		if !allowPrivate && isDisallowedIP(u) {
			return SendOutcome{Err: fmt.Errorf("smtp egress blocked to %s", u)}
		}
		verifiedIPs = append(verifiedIPs, u)
	}
	portStr := strconv.Itoa(cfg.SMTPPort)
	dialer := &net.Dialer{Deadline: deadline}
	var conn net.Conn
	var dialErr error
	for _, verifiedIP := range verifiedIPs {
		targetAddr := net.JoinHostPort(verifiedIP.String(), portStr)
		if cfg.SMTPTLS || cfg.SMTPPort == 465 {
			td := &tls.Dialer{
				NetDialer: dialer,
				Config:    &tls.Config{ServerName: cfg.SMTPHost, MinVersion: tls.VersionTLS12},
			}
			conn, dialErr = td.DialContext(ctx, "tcp", targetAddr)
		} else {
			conn, dialErr = dialer.DialContext(ctx, "tcp", targetAddr)
		}
		if dialErr == nil {
			break
		}
	}
	if dialErr != nil {
		return SendOutcome{Err: dialErr}
	}
	_ = conn.SetDeadline(deadline)
	c, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return SendOutcome{Err: err}
	}
	defer func() { _ = c.Close() }()
	if !cfg.SMTPTLS && cfg.SMTPPort != 465 {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: cfg.SMTPHost, MinVersion: tls.VersionTLS12}); err != nil {
				return SendOutcome{Err: err}
			}
		}
	}
	if cfg.SMTPUser != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)); err != nil {
			return SendOutcome{Err: err}
		}
	}
	if err := c.Mail(cfg.SMTPFrom); err != nil {
		return SendOutcome{Err: err}
	}
	for _, rcpt := range cfg.SMTPTo {
		if err := c.Rcpt(rcpt); err != nil {
			return SendOutcome{Err: err}
		}
	}
	w, err := c.Data()
	if err != nil {
		return SendOutcome{Err: err}
	}
	encodedSubject := encodeRFC2047Subject(severityBadge(ev.Severity) + " " + ev.Title)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n",
		cfg.SMTPFrom, strings.Join(cfg.SMTPTo, ", "), encodedSubject, formatPlainText(ev))
	if _, err := io.WriteString(w, msg); err != nil {
		_ = w.Close()
		return SendOutcome{Err: err}
	}
	if err := w.Close(); err != nil {
		return SendOutcome{Err: err}
	}
	_ = c.Quit()
	return SendOutcome{HTTPStatus: 250}
}
