// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/sandbox"
	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// Config configures the Host service of one plugin instance.
//
// Every dependency is a narrow interface so the Agent can wire the real host
// components (internal/storage, internal/events, internal/secrets,
// internal/operations) without this package importing them, and so tests can
// substitute fakes. A nil optional dependency makes the affected RPCs fail
// with UNAVAILABLE instead of silently doing nothing; Peer is mandatory
// because a listener without peer verification would be open to every local
// process.
type Config struct {
	// PluginID and InstanceID name the plugin instance this listener serves.
	// Caller identity for host-side work comes from these fields and from the
	// verified peer, never from HostCallContext.
	PluginID   string
	InstanceID string

	// SocketPath is the Unix domain socket the host service listens on. Its
	// parent directory must already exist: the root helper creates it as
	// <agent>:qwq-p-<id> 2750 at install time (PRIV-04), and the setgid bit
	// makes the 0660 socket inherit the plugin group. The directory is only
	// verified: a real directory owned by this process and not group/world
	// writable.
	SocketPath string

	// CreateSocketDir creates a missing socket directory (0750). Only unit
	// tests set it; production must never create the directory itself.
	CreateSocketDir bool

	// TokenDigest returns the SHA-256 of the plugin token. When it is set,
	// every RPC must carry exactly one pluginsdk.HostTokenMetadataKey value
	// whose digest matches (constant-time); anything else is UNAUTHENTICATED
	// (PRIV-05, ADR-0013). It is consulted per call, so a token rotated by a
	// reinstall takes effect without rebuilding the server. Nil disables the
	// check (unit tests and processes without a credential store); an error
	// rejects the call.
	TokenDigest func(ctx context.Context) ([]byte, error)
	// TokenDigests 供受控轮换返回当前/上一槽，最多两个 SHA-256；每次 RPC
	// 都重新读取。与 TokenDigest 互斥，存储错误不能回退到无认证或旧配置。
	TokenDigests func(ctx context.Context) ([][]byte, error)

	// StateDir holds the built-in state store (StateDir/state.json, mode
	// 0600). It is required when State is nil.
	StateDir string

	// Clock is the time source for audit timestamps and rate limits. The
	// default is the system clock.
	Clock clock.Clock

	// Logger receives peer rejections, sink failures and slow-subscriber
	// warnings. The default discards everything.
	Logger *slog.Logger

	// State is the per-instance key/value store. Nil selects the built-in file
	// store below StateDir.
	State StateStore
	// Events receives published events and resource changes. Nil makes
	// PublishEvent and ReportChanges fail with UNAVAILABLE.
	Events EventSink
	// Config provides the current config snapshot. Nil makes GetConfig fail
	// with UNAVAILABLE.
	Config ConfigSource
	// Secrets reveals secret references. Nil makes RevealSecret fail with
	// UNAVAILABLE.
	Secrets SecretRevealer
	// Audit receives plugin-written audit records. Nil makes WriteAudit fail
	// with UNAVAILABLE and makes a plugin-triggered secret reveal fail closed.
	Audit AuditSink
	// Invoke mediates plugin-to-plugin calls. Nil makes the HostInvokeService
	// RPCs fail with UNAVAILABLE.
	Invoke Invoker

	// GrantedCapabilities 来自宿主验签后的 manifest。New 复制快照；插件消息
	// 不能新增能力。服务按能力名称选择性注册，每个 RPC 再核验 scope。
	GrantedCapabilities []*platformv1.Capability
	// OperationResolver 绑定所有能力写入到本实例正在运行的 operation。
	OperationResolver OperationResolver
	// AutonomousChecker 核验后台守护实例是否被 manifest 授权且处于活跃态，
	// 仅在此前提下放行白名单内的 auton:* 后台自治能力写调用。
	AutonomousChecker AutonomousInstanceChecker
	// CapabilityForwarder 注入宿主事实并执行经过授权的能力调用。
	CapabilityForwarder CapabilityForwarder
	// OnEventPublished 在 PublishEvent 落库成功后旁路通知宿主事件桥（如 notify.hub 告警中继）。
	OnEventPublished func(pluginID string, draft *platformv1.EventDraft, assignedEventID string)

	// Peer authenticates every accepted connection. Required.
	Peer PeerVerifier

	// Limits bounds message sizes, queues, quotas and timeouts. The zero value
	// applies the defaults documented on Limits.
	Limits Limits
}

// Limits bounds the resources of one host service. Zero fields take the
// documented default; negative sizes are rejected by New.
type Limits struct {
	// MaxRequestBytes is the gRPC receive and send limit. Default 4 MiB (the
	// ABI message limit).
	MaxRequestBytes int
	// RequestTimeout caps every unary call, even when the plugin sends no
	// deadline. Default 30 s.
	RequestTimeout time.Duration
	// StreamTimeout caps one SubscribeEvents stream. Default 1 h.
	StreamTimeout time.Duration

	// MaxKeyBytes is the maximum state key length. Default 256 (the ABI
	// grammar allows 1-256 bytes).
	MaxKeyBytes int
	// MaxValueBytes is the maximum state value size. Default 1 MiB (the ABI
	// limit for one JSON document).
	MaxValueBytes int
	// MaxTotalBytes is the total size of one instance's state (keys plus
	// values). Default 4 MiB; the Agent derives it from the manifest field
	// resources.kv_max_kb with KVMaxBytes.
	MaxTotalBytes int64
	// PageSize is the ListState page size when the request asks for 0.
	// Default 100.
	PageSize int
	// MaxPageSize caps a requested ListState page size. Default 1000.
	MaxPageSize int

	// MaxChanges is the number of ResourceChange entries accepted in one
	// ReportChanges call. Default 256.
	MaxChanges int
	// MaxEventBytes is the maximum event payload. Default 1 MiB.
	MaxEventBytes int
	// EventSpool is the number of PublishEvent calls that may be in flight.
	// Default 1024. A full spool is RESOURCE_EXHAUSTED.
	EventSpool int
	// EventSpoolBytes bounds the retained event buffer used by subscribers.
	// Default 8 MiB.
	EventSpoolBytes int64
	// MaxSubscriptions bounds concurrent SubscribeEvents streams. Default 32.
	MaxSubscriptions int
	// MaxSubscriptionCursors bounds the number of distinct durable
	// subscription names whose ack cursor the server remembers. Default 1024;
	// a plugin that keeps inventing names eventually gets RESOURCE_EXHAUSTED.
	MaxSubscriptionCursors int

	// AuditQueue bounds in-flight audit writes of this plugin. Default 256.
	AuditQueue int
	// AuditPerMinute is the plugin audit quota. Default 120 records per
	// minute.
	AuditPerMinute int
	// SecretRevealsPerMinute is the per-plugin reveal quota. Default 30.
	SecretRevealsPerMinute int
	// CapabilityWritesPerMinute 是能力写调用限频，默认 60/min。
	CapabilityWritesPerMinute int
	// AutonomousWritesPerMinute 是后台自治能力写调用限频，默认 12/min。
	AutonomousWritesPerMinute int
	// BanScansPerMinute 是 journald 扫描限频，默认 6/min。
	BanScansPerMinute int
	// MetricsReadsPerMinute 是 metrics 读限频，默认 120/min、突发 2。
	MetricsReadsPerMinute int
	// WaitTimeout caps WaitOperation. Default 60 s (the ABI cap).
	WaitTimeout time.Duration
	// ShutdownTimeout is how long Close waits for in-flight calls before it
	// stops the server. Default 5 s.
	ShutdownTimeout time.Duration
}

// Sizes and defaults from the ABI and from the limits documented on Limits.
const (
	DefaultMaxRequestBytes        = 4 << 20
	DefaultRequestTimeout         = 30 * time.Second
	DefaultStreamTimeout          = time.Hour
	DefaultMaxKeyBytes            = 256
	DefaultMaxValueBytes          = 1 << 20
	DefaultMaxTotalBytes          = 4 << 20
	DefaultPageSize               = 100
	DefaultMaxPageSize            = 1000
	DefaultMaxChanges             = 256
	DefaultMaxEventBytes          = 1 << 20
	DefaultEventSpool             = 1024
	DefaultEventSpoolBytes        = 8 << 20
	DefaultMaxSubscriptions       = 32
	DefaultMaxSubscriptionCursors = 1024
	DefaultAuditQueue             = 256
	DefaultAuditPerMinute         = 1200
	DefaultSecretReveals          = 1200
	DefaultCapabilityWrites       = 60
	DefaultAutonomousWrites       = 12
	DefaultBanScans               = 6
	DefaultMetricsReads           = 120
	DefaultWaitTimeout            = 60 * time.Second
	DefaultShutdownTimeout        = 5 * time.Second
)

// DefaultLimits returns Limits with every field set to its default. Callers
// that need to change one value can start from this and avoid restating the
// other defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxRequestBytes:           DefaultMaxRequestBytes,
		RequestTimeout:            DefaultRequestTimeout,
		StreamTimeout:             DefaultStreamTimeout,
		MaxKeyBytes:               DefaultMaxKeyBytes,
		MaxValueBytes:             DefaultMaxValueBytes,
		MaxTotalBytes:             DefaultMaxTotalBytes,
		PageSize:                  DefaultPageSize,
		MaxPageSize:               DefaultMaxPageSize,
		MaxChanges:                DefaultMaxChanges,
		MaxEventBytes:             DefaultMaxEventBytes,
		EventSpool:                DefaultEventSpool,
		EventSpoolBytes:           DefaultEventSpoolBytes,
		MaxSubscriptions:          DefaultMaxSubscriptions,
		MaxSubscriptionCursors:    DefaultMaxSubscriptionCursors,
		AuditQueue:                DefaultAuditQueue,
		AuditPerMinute:            DefaultAuditPerMinute,
		SecretRevealsPerMinute:    DefaultSecretReveals,
		CapabilityWritesPerMinute: DefaultCapabilityWrites,
		AutonomousWritesPerMinute: DefaultAutonomousWrites,
		BanScansPerMinute:         DefaultBanScans,
		MetricsReadsPerMinute:     DefaultMetricsReads,
		WaitTimeout:               DefaultWaitTimeout,
		ShutdownTimeout:           DefaultShutdownTimeout,
	}
}

// KVMaxBytes converts the manifest field resources.kv_max_kb into the byte
// limit Config.Limits.MaxTotalBytes expects. A non-positive value keeps the
// default.
func KVMaxBytes(kvMaxKB int) int64 {
	if kvMaxKB <= 0 {
		return DefaultMaxTotalBytes
	}
	return int64(kvMaxKB) << 10
}

// withDefaults returns l with every zero field replaced by its default.
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxRequestBytes == 0 {
		l.MaxRequestBytes = d.MaxRequestBytes
	}
	if l.RequestTimeout == 0 {
		l.RequestTimeout = d.RequestTimeout
	}
	if l.StreamTimeout == 0 {
		l.StreamTimeout = d.StreamTimeout
	}
	if l.MaxKeyBytes == 0 {
		l.MaxKeyBytes = d.MaxKeyBytes
	}
	if l.MaxValueBytes == 0 {
		l.MaxValueBytes = d.MaxValueBytes
	}
	if l.MaxTotalBytes == 0 {
		l.MaxTotalBytes = d.MaxTotalBytes
	}
	if l.PageSize == 0 {
		l.PageSize = d.PageSize
	}
	if l.MaxPageSize == 0 {
		l.MaxPageSize = d.MaxPageSize
	}
	if l.MaxChanges == 0 {
		l.MaxChanges = d.MaxChanges
	}
	if l.MaxEventBytes == 0 {
		l.MaxEventBytes = d.MaxEventBytes
	}
	if l.EventSpool == 0 {
		l.EventSpool = d.EventSpool
	}
	if l.EventSpoolBytes == 0 {
		l.EventSpoolBytes = d.EventSpoolBytes
	}
	if l.MaxSubscriptions == 0 {
		l.MaxSubscriptions = d.MaxSubscriptions
	}
	if l.MaxSubscriptionCursors == 0 {
		l.MaxSubscriptionCursors = d.MaxSubscriptionCursors
	}
	if l.AuditQueue == 0 {
		l.AuditQueue = d.AuditQueue
	}
	if l.AuditPerMinute == 0 {
		l.AuditPerMinute = d.AuditPerMinute
	}
	if l.SecretRevealsPerMinute == 0 {
		l.SecretRevealsPerMinute = d.SecretRevealsPerMinute
	}
	if l.CapabilityWritesPerMinute == 0 {
		l.CapabilityWritesPerMinute = d.CapabilityWritesPerMinute
	}
	if l.AutonomousWritesPerMinute == 0 {
		l.AutonomousWritesPerMinute = d.AutonomousWritesPerMinute
	}
	if l.BanScansPerMinute == 0 {
		l.BanScansPerMinute = d.BanScansPerMinute
	}
	if l.MetricsReadsPerMinute == 0 {
		l.MetricsReadsPerMinute = d.MetricsReadsPerMinute
	}
	if l.WaitTimeout == 0 {
		l.WaitTimeout = d.WaitTimeout
	}
	if l.ShutdownTimeout == 0 {
		l.ShutdownTimeout = d.ShutdownTimeout
	}
	return l
}

// validate rejects negative and inconsistent limits.
func (l Limits) validate() error {
	type field struct {
		name string
		n    int64
	}
	for _, f := range []field{
		{"MaxRequestBytes", int64(l.MaxRequestBytes)},
		{"MaxKeyBytes", int64(l.MaxKeyBytes)},
		{"MaxValueBytes", int64(l.MaxValueBytes)},
		{"MaxTotalBytes", l.MaxTotalBytes},
		{"PageSize", int64(l.PageSize)},
		{"MaxPageSize", int64(l.MaxPageSize)},
		{"MaxChanges", int64(l.MaxChanges)},
		{"MaxEventBytes", int64(l.MaxEventBytes)},
		{"EventSpool", int64(l.EventSpool)},
		{"EventSpoolBytes", l.EventSpoolBytes},
		{"MaxSubscriptions", int64(l.MaxSubscriptions)},
		{"MaxSubscriptionCursors", int64(l.MaxSubscriptionCursors)},
		{"AuditQueue", int64(l.AuditQueue)},
		{"AuditPerMinute", int64(l.AuditPerMinute)},
		{"SecretRevealsPerMinute", int64(l.SecretRevealsPerMinute)},
		{"CapabilityWritesPerMinute", int64(l.CapabilityWritesPerMinute)},
		{"AutonomousWritesPerMinute", int64(l.AutonomousWritesPerMinute)},
		{"BanScansPerMinute", int64(l.BanScansPerMinute)},
		{"MetricsReadsPerMinute", int64(l.MetricsReadsPerMinute)},
	} {
		if f.n <= 0 {
			return fmt.Errorf("hostsvc: limits.%s must be positive", f.name)
		}
	}
	for _, d := range []struct {
		name string
		v    time.Duration
	}{
		{"RequestTimeout", l.RequestTimeout},
		{"StreamTimeout", l.StreamTimeout},
		{"WaitTimeout", l.WaitTimeout},
		{"ShutdownTimeout", l.ShutdownTimeout},
	} {
		if d.v <= 0 {
			return fmt.Errorf("hostsvc: limits.%s must be positive", d.name)
		}
	}
	if int64(l.MaxValueBytes) > l.MaxTotalBytes {
		return errors.New("hostsvc: limits.MaxValueBytes exceeds limits.MaxTotalBytes")
	}
	if l.PageSize > l.MaxPageSize {
		return errors.New("hostsvc: limits.PageSize exceeds limits.MaxPageSize")
	}
	return nil
}

// validate checks the required fields. It runs before any goroutine or file is
// created so a wiring mistake fails at startup, not on the first call.
func (c Config) validate() error {
	if c.TokenDigest != nil && c.TokenDigests != nil {
		return errors.New("hostsvc: only one plugin credential provider may be configured")
	}
	if err := checkName("plugin_id", c.PluginID, 128); err != nil {
		return err
	}
	if err := checkName("instance_id", c.InstanceID, 128); err != nil {
		return err
	}
	if c.SocketPath == "" {
		return errors.New("hostsvc: SocketPath is required")
	}
	if !filepath.IsAbs(c.SocketPath) {
		return errors.New("hostsvc: SocketPath must be absolute")
	}
	// Linux sun_path is 108 bytes including the terminating NUL, so the
	// longest usable path is 107 bytes. Reject longer paths here instead of
	// letting Listen fail with a bare invalid-argument error.
	if len(c.SocketPath) > 107 {
		return fmt.Errorf("hostsvc: SocketPath is longer than the 107 bytes a Linux Unix socket can hold")
	}
	if c.State == nil && c.StateDir == "" {
		return errors.New("hostsvc: StateDir is required when State is nil")
	}
	if c.Peer == nil {
		return errors.New("hostsvc: Peer verifier is required")
	}
	return nil
}

// checkName validates an identifier whose characters are [A-Za-z0-9._-] and
// whose first character is alphanumeric.
func checkName(field, value string, maxLen int) error {
	if value == "" {
		return fmt.Errorf("hostsvc: %s is required", field)
	}
	if len(value) > maxLen {
		return fmt.Errorf("hostsvc: %s is longer than %d bytes", field, maxLen)
	}
	if !validIdentifier(value, maxLen) {
		return fmt.Errorf("hostsvc: %s must match [A-Za-z0-9][A-Za-z0-9._-]*", field)
	}
	return nil
}

// ensureDir creates dir with mode 0750 when it does not exist. An existing
// directory keeps its mode: the Agent's supervisor may have created it with a
// private group and the setgid bit (spikes/p2t1/REPORT.md §3).
func ensureDir(dir string) error {
	if dir == "" || dir == "." {
		return errors.New("hostsvc: empty directory")
	}
	_, statErr := os.Stat(dir)
	existed := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if !existed {
		if err := os.Chmod(dir, 0o750); err != nil {
			return err
		}
	}
	return nil
}

// checkSocketDir verifies the helper-created socket directory: a real
// directory (not a symlink) owned by the effective user, with no group or
// world write bit. allowCreate creates a missing directory first (tests only).
func checkSocketDir(dir string, allowCreate bool) error {
	if allowCreate {
		if err := ensureDir(dir); err != nil {
			return err
		}
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("hostsvc: %s is not a real directory", dir)
	}
	if uid, ok := sandbox.FileOwner(fi); !ok || uid != os.Geteuid() {
		return fmt.Errorf("hostsvc: %s is not owned by uid %d", dir, os.Geteuid())
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("hostsvc: %s is group or world writable", dir)
	}
	return nil
}

// clipString truncates s to n bytes on a rune boundary. It is for untrusted
// correlation fields that must not grow a log line or a status message.
func clipString(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8RuneStart(s[n]) {
		n--
	}
	return strings.TrimSpace(s[:n])
}

// utf8RuneStart reports whether b is the first byte of a UTF-8 encoding.
func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }
