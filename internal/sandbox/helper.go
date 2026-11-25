// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// The privileged helper is the only component that writes the plugin units,
// the tmpfiles snippets and the runtime directories. The controller runs as the
// unprivileged qwq user and cannot write /etc/systemd/system, so
// PluginInstaller hands it a UnitSpec over a Unix socket and the root helper
// performs the write (P3 real-systemd install).
//
// The wire format is one JSON object per connection in each direction,
// terminated by a newline. The helper is socket activated and handles one
// request per activation, so an idle host runs no helper process at all.
const (
	// DefaultPrivilegedSocket is where deployments/systemd/qwq-privileged.socket
	// listens. The socket is root:qwq 0660 so the controller can connect but no
	// plugin (DynamicUser) can.
	DefaultPrivilegedSocket = "/run/qwq/privileged.sock"

	// MaxHelperMessage bounds one request or one response. A unit spec and a
	// token are far below it; the cap keeps a hostile or broken client from
	// making the root process allocate an unbounded buffer.
	MaxHelperMessage = 1 << 20

	// DefaultHelperTimeout bounds one helper call, including the connection.
	DefaultHelperTimeout = 30 * time.Second
)

// Helper operations.
const (
	HelperOpInstall = "install"
	HelperOpRemove  = "remove"
	HelperOpReload  = "reload"
	HelperOpPing    = "ping"
	// HelperOpPublish copies a verified staging tree into the immutable
	// version directory. The controller stages and verifies the package as
	// qwq, but /var/lib/qwq-plugins belongs to root, so only the helper can
	// create the version directory.
	HelperOpPublish = "publish"
	// HelperOpLogs reads the journal of one plugin unit. It is read-only: the
	// helper builds every journalctl argument itself and only ever addresses
	// qwq-plugin@<id>.service (GAPS gap 7).
	HelperOpLogs = "logs"
	// HelperOpBackupPluginData snapshots DynamicUser plugin private data trees
	// (including consistent SQLite VACUUM INTO copies) into a root-owned
	// read-only backup staging directory (0750 root:qwq) so `qwq backup` can
	// archive full plugin state without running as root.
	HelperOpBackupPluginData = "backup-plugin-data"
	// HelperOpBackupPluginCleanup removes a root-owned plugin backup staging
	// directory created by HelperOpBackupPluginData after archiving completes.
	HelperOpBackupPluginCleanup = "backup-plugin-cleanup"
	// HelperOpUpdateResources writes or removes the user resource limit override
	// drop-in (20-user-resources.conf) for a plugin systemd unit and reloads systemd.
	HelperOpUpdateResources = "update-resources"
)

// Log limits of the helper. MaxLogLines keeps one response well inside
// MaxHelperMessage even when every line is truncated at MaxLogLineBytes.
const (
	DefaultLogLines  = 50
	MaxLogLines      = 100
	MaxLogLineBytes  = 4 << 10
	maxLogCursorSize = 512
)

// helperDialAttempts and helperRetryBackoff control the connect retry. Only a
// failed connect is retried: once the request reached the helper a retry could
// install or remove the same plugin twice.
var (
	helperDialAttempts = 3
	helperRetryBackoff = 50 * time.Millisecond
)

// HelperRequest is one request object. Which fields are used depends on Op:
//
//	install  Spec, CredentialBase64
//	remove   ID, Version, Paths, KeepUnit, PurgeData
//	publish  StagedDir, VersionDir, PluginID, Version
//	reload   (none)
//	ping     (none)
//
// The type is shared by the client and by cmd/qwq-privileged so both sides
// decode the same schema; the server rejects unknown fields, so a typo cannot
// silently fall back to a default.
type HelperRequest struct {
	Op               string    `json:"op"`
	Spec             *UnitSpec `json:"spec,omitempty"`
	CredentialBase64 string    `json:"credential_base64,omitempty"`
	ID               string    `json:"id,omitempty"`
	Version          string    `json:"version,omitempty"`
	Paths            []string  `json:"paths,omitempty"`
	KeepUnit         bool      `json:"keep_unit,omitempty"`
	// PurgeData 只删除 root 配置派生的本插件数据，不接收任意数据路径。
	PurgeData bool `json:"purge_data,omitempty"`
	// StagedDir, VersionDir and PluginID are the publish fields. Version is
	// shared with remove; both name a single path component.
	StagedDir  string `json:"staged_dir,omitempty"`
	VersionDir string `json:"version_dir,omitempty"`
	PluginID   string `json:"plugin_id,omitempty"`
	// Cursor, Limit and Stream are the logs fields. Cursor is a journald cursor
	// the caller received as NextCursor; empty starts at the most recent window.
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Stream string `json:"stream,omitempty"`
	// BackupSpecs and BackupStageName are the backup-plugin-data fields.
	BackupSpecs     []PluginBackupSpec `json:"backup_specs,omitempty"`
	BackupStageName string             `json:"backup_stage_name,omitempty"`
	// Limits and ResetResources are the update-resources fields.
	Limits         *Limits `json:"limits,omitempty"`
	ResetResources bool    `json:"reset_resources,omitempty"`
}

// PluginBackupSpec declares which relative paths inside one plugin's private
// StateDirectory (<PrivateDataRoot>/<PluginID>/default) should be snapshotted.
type PluginBackupSpec struct {
	PluginID    string   `json:"plugin_id"`
	BackupPaths []string `json:"backup_paths"`
}

// PluginBackupResult reports the staged plugin backup directory and plugins.
type PluginBackupResult struct {
	StageDir      string   `json:"stage_dir"`
	StagedPlugins []string `json:"staged_plugins,omitempty"`
}

// HelperLogs is the client-side form of a logs request.
type HelperLogs struct {
	ID     string
	Cursor string
	Stream string
	Limit  int
}

// LogLine is one journal line of a plugin. Line is untrusted plugin text,
// truncated at MaxLogLineBytes.
type LogLine struct {
	At     string `json:"at"`
	Stream string `json:"stream"`
	Line   string `json:"line"`
}

// LogResult is one page of plugin journal lines, oldest first within the page.
// NextCursor is the cursor of the last line: passing it back reads what came
// after it, so a viewer follows the log forward.
type LogResult struct {
	Lines      []LogLine `json:"lines"`
	NextCursor string    `json:"next_cursor,omitempty"`
	Truncated  bool      `json:"truncated"`
}

// HelperResponse is one response object. OK is authoritative: a false value
// carries Code (a problem code) and Error (a human-readable detail). Warnings
// report a partially successful operation, currently a plugin socket unit that
// could not be enabled after the files were written or disabled before they
// were removed.
type HelperResponse struct {
	OK           bool                `json:"ok"`
	Code         string              `json:"code,omitempty"`
	Error        string              `json:"error,omitempty"`
	Install      *InstallResult      `json:"install,omitempty"`
	Remove       *RemoveResult       `json:"remove,omitempty"`
	Publish      *PublishResult      `json:"publish,omitempty"`
	Logs         *LogResult          `json:"logs,omitempty"`
	PluginBackup *PluginBackupResult `json:"plugin_backup,omitempty"`
	Warnings     []string            `json:"warnings,omitempty"`
	Version      string              `json:"version,omitempty"`
	// UID is the helper's effective uid. It is not omitempty: the ping reply
	// must show 0 explicitly, and a non-zero value would mean the helper is
	// not running as root.
	UID int `json:"uid"`
}

// HelperPublish is the client-side form of a publish request.
type HelperPublish struct {
	// StagedDir is the verified staging directory
	// (<staging-root>/.staging-*). The helper only reads it.
	StagedDir string
	// VersionDir is the immutable target
	// <plugins-root>/<id>/<version>.
	VersionDir string
	// PluginID is the manifest plugin id and must match both paths.
	PluginID string
	// Version is the manifest version and must match VersionDir.
	Version string
}

// PublishResult reports a published (or already published) version directory.
// Existing is true when the directory was already there with identical
// content, which is the idempotent path.
type PublishResult struct {
	ID         string `json:"id"`
	Version    string `json:"version"`
	VersionDir string `json:"version_dir"`
	Files      int    `json:"files"`
	Dirs       int    `json:"dirs"`
	Existing   bool   `json:"existing,omitempty"`
}

// HelperRemove is the client-side form of a remove request.
type HelperRemove struct {
	// ID is the plugin id.
	ID string
	// Version is the installed version whose directory is removed. Empty is
	// allowed when Paths is empty.
	Version string
	// Paths lists the version directories to delete. The helper accepts only
	// <plugins root>/<ID>/<Version>.
	Paths []string
	// KeepUnit keeps the unit files when another version of the plugin is
	// still installed.
	KeepUnit bool
	// PurgeData 显式清理本插件的持久数据，仅完整卸载使用。
	PurgeData bool
}

// HelperPing is the reply to a ping.
type HelperPing struct {
	Version string
	UID     int
}

// HelperClient talks to the root helper. The zero value is not usable; build it
// with NewHelperClient. It is safe for concurrent use: every call opens its own
// connection.
type HelperClient struct {
	// Socket is the helper's Unix socket (default when empty is not applied:
	// an empty socket is an error so a missing flag cannot silently target
	// something else).
	Socket string
	// Timeout bounds one call; zero means DefaultHelperTimeout.
	Timeout time.Duration

	// dial is a test seam for the connect retry; production uses net.Dialer.
	dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// NewHelperClient returns a client for socket.
func NewHelperClient(socket string) *HelperClient {
	return &HelperClient{Socket: socket}
}

// Install asks the helper to write the unit, the drop-in, the tmpfiles snippet,
// the credential and the runtime directories of one plugin, and to enable its
// socket. credential may be nil.
func (c *HelperClient) Install(ctx context.Context, spec UnitSpec, credential []byte) (InstallResult, error) {
	var res InstallResult
	req := HelperRequest{Op: HelperOpInstall, Spec: &spec}
	if credential != nil {
		req.CredentialBase64 = base64.StdEncoding.EncodeToString(credential)
	}
	resp, err := c.call(ctx, req)
	if err != nil {
		return res, err
	}
	if resp.Install == nil {
		return res, problem.New(problem.Internal,
			"The privileged helper did not report the files it installed.")
	}
	res = *resp.Install
	res.Warnings = resp.Warnings
	return res, nil
}

// Publish asks the helper to copy a verified staging tree into the immutable
// version directory. The report says whether the directory already existed
// with identical content (Existing).
func (c *HelperClient) Publish(ctx context.Context, req HelperPublish) (PublishResult, error) {
	var res PublishResult
	resp, err := c.call(ctx, HelperRequest{
		Op:         HelperOpPublish,
		StagedDir:  req.StagedDir,
		VersionDir: req.VersionDir,
		PluginID:   req.PluginID,
		Version:    req.Version,
	})
	if err != nil {
		return res, err
	}
	if resp.Publish == nil {
		return res, problem.New(problem.Internal,
			"The privileged helper did not report the published version.")
	}
	return *resp.Publish, nil
}

// UpdateResources asks the helper to write or remove the user resource limit
// drop-in (20-user-resources.conf) for plugin id and reload systemd.
func (c *HelperClient) UpdateResources(ctx context.Context, id string, limits *Limits, reset bool) error {
	_, err := c.call(ctx, HelperRequest{
		Op:             HelperOpUpdateResources,
		ID:             id,
		Limits:         limits,
		ResetResources: reset,
	})
	return err
}

// Remove asks the helper to delete a version directory and, unless KeepUnit is
// set, the unit artifacts of the plugin. The helper refuses while the unit has
// a main process.
func (c *HelperClient) Remove(ctx context.Context, req HelperRemove) (RemoveResult, error) {
	var res RemoveResult
	resp, err := c.call(ctx, HelperRequest{
		Op:        HelperOpRemove,
		ID:        req.ID,
		Version:   req.Version,
		Paths:     req.Paths,
		KeepUnit:  req.KeepUnit,
		PurgeData: req.PurgeData,
	})
	if err != nil {
		return res, err
	}
	if resp.Remove == nil {
		return res, problem.New(problem.Internal,
			"The privileged helper did not report what it removed.")
	}
	res = *resp.Remove
	res.Warnings = resp.Warnings
	return res, nil
}

// Logs reads one page of a plugin unit's journal through the helper.
func (c *HelperClient) Logs(ctx context.Context, req HelperLogs) (LogResult, error) {
	var res LogResult
	resp, err := c.call(ctx, HelperRequest{
		Op: HelperOpLogs, ID: req.ID, Cursor: req.Cursor, Limit: req.Limit, Stream: req.Stream,
	})
	if err != nil {
		return res, err
	}
	if resp.Logs == nil {
		return res, problem.New(problem.Internal, "The privileged helper did not report any log page.")
	}
	return *resp.Logs, nil
}

// Reload asks the helper to run `systemctl daemon-reload`.
func (c *HelperClient) Reload(ctx context.Context) error {
	_, err := c.call(ctx, HelperRequest{Op: HelperOpReload})
	return err
}

// Ping checks that the helper is reachable and root.
func (c *HelperClient) Ping(ctx context.Context) (HelperPing, error) {
	resp, err := c.call(ctx, HelperRequest{Op: HelperOpPing})
	if err != nil {
		return HelperPing{}, err
	}
	return HelperPing{Version: resp.Version, UID: resp.UID}, nil
}

// BackupPluginData asks the privileged helper to snapshot the declared
// DynamicUser plugin private data directories into a root-owned backup staging
// directory readable by the agent group.
func (c *HelperClient) BackupPluginData(ctx context.Context, stageName string, specs []PluginBackupSpec) (PluginBackupResult, error) {
	client := *c
	if client.Timeout == 0 {
		client.Timeout = 3 * time.Minute
	}
	resp, err := client.call(ctx, HelperRequest{
		Op:              HelperOpBackupPluginData,
		BackupStageName: stageName,
		BackupSpecs:     specs,
	})
	if err != nil {
		return PluginBackupResult{}, err
	}
	if resp.PluginBackup == nil {
		return PluginBackupResult{}, problem.New(problem.Internal,
			"The privileged helper did not report the staged plugin backup directory.")
	}
	return *resp.PluginBackup, nil
}

// BackupPluginCleanup asks the privileged helper to remove a root-owned plugin
// backup staging directory created by BackupPluginData.
func (c *HelperClient) BackupPluginCleanup(ctx context.Context, stageName string) error {
	_, err := c.call(ctx, HelperRequest{
		Op:              HelperOpBackupPluginCleanup,
		BackupStageName: stageName,
	})
	return err
}

// call performs one request/response exchange. It retries only the connect.
func (c *HelperClient) call(ctx context.Context, req HelperRequest) (HelperResponse, error) {
	var zero HelperResponse
	var resp HelperResponse
	if err := c.exchange(ctx, req, &resp); err != nil {
		return zero, err
	}
	if !resp.OK {
		return zero, helperRemoteFailure(resp)
	}
	return resp, nil
}

// connect dials the helper, retrying only a failed connect.
func (c *HelperClient) connect(ctx context.Context) (net.Conn, error) {
	attempts := helperDialAttempts
	if attempts < 1 {
		attempts = 1
	}
	dial := c.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	var last error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(helperRetryBackoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
		conn, err := dial(ctx, "unix", c.Socket)
		if err == nil {
			return conn, nil
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("connecting to %s: %w", c.Socket, last)
}

// helperTransportFailure maps a connection, deadline or protocol failure.
func helperTransportFailure(action string, err error) error {
	if errorIsTimeout(err) {
		return &problem.Error{
			Code:   problem.Timeout,
			Detail: "The privileged helper did not answer before its deadline.",
			Cause:  err,
		}
	}
	return &problem.Error{
		Code:   problem.Unavailable,
		Detail: fmt.Sprintf("The privileged helper could not %s.", action),
		Cause:  err,
	}
}

// errorIsTimeout reports a deadline from the connection (os.ErrDeadlineExceeded
// is not context.DeadlineExceeded and net.Error.Timeout covers both).
func errorIsTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// helperRemoteFailure converts a refused request into a host error. An unknown
// code is reported as INTERNAL instead of forwarding an undocumented code.
func helperRemoteFailure(resp HelperResponse) error {
	code := problem.Code(resp.Code)
	if !code.Known() {
		code = problem.Internal
	}
	detail := resp.Error
	if detail == "" {
		detail = "The privileged helper refused the request."
	}
	return &problem.Error{Code: code, Detail: detail}
}

// WriteHelperJSON writes exactly one newline-terminated JSON object. It refuses
// a message larger than its protocol's limit before writing anything.
func WriteHelperJSON(w io.Writer, v any) error {
	if w == nil {
		return errors.New("sandbox: helper message writer is nil")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("sandbox: encoding the helper message: %w", err)
	}
	limit := helperMessageLimit(v)
	if len(b) > limit {
		return fmt.Errorf("sandbox: the helper message is %d bytes, the limit is %d", len(b), limit)
	}
	b = append(b, '\n')
	defer clear(b)
	if written, err := w.Write(b); err != nil {
		return fmt.Errorf("sandbox: writing the helper message: %w", err)
	} else if written != len(b) {
		return io.ErrShortWrite
	}
	return nil
}

// ReadHelperJSON reads exactly one newline-terminated JSON object. The newline
// lets a peer answer without closing the connection first; a message is
// complete at the delimiter.
func ReadHelperJSON(r io.Reader, v any) error {
	if r == nil {
		return errors.New("sandbox: helper message reader is nil")
	}
	reader, ok := r.(*bufio.Reader)
	if !ok {
		reader = bufio.NewReaderSize(r, 64<<10)
	}
	raw, err := ReadHelperDocument(reader)
	defer clear(raw)
	if err != nil {
		return err
	}
	return DecodeHelperDocument(raw, v)
}

// ======================== 单份有界分帧：保留 reader 中已预读的后续字节 ========================

// ReadHelperDocument 只分出一帧；调用方保留 reader，并负责清理返回的原文。
// reader 不会被重新包装，第二帧仍可被 server 的单请求门禁与取消监听发现。
func ReadHelperDocument(reader *bufio.Reader) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("sandbox: helper message reader is nil")
	}
	var document []byte
	for {
		part, err := reader.ReadSlice('\n')
		if len(document)+len(part) > MaxHelperMessage+2 {
			clear(document)
			return nil, errors.New("sandbox: helper frame exceeds its size limit")
		}
		document = append(document, part...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			clear(document)
			return nil, fmt.Errorf("sandbox: reading the helper message: %w", err)
		}
		document = bytes.TrimSuffix(document, []byte{'\n'})
		document = bytes.TrimSuffix(document, []byte{'\r'})
		if len(document) > MaxHelperMessage {
			clear(document)
			return nil, errors.New("sandbox: helper frame exceeds its size limit")
		}
		return document, nil
	}
}

// DecodeHelperDocument 校验完整的有界 JSON 对象，允许对象内的换行。
// wire 读取仍由 ReadHelperJSON 按单行分帧；两者共用重复键、深度及字段检查。
func DecodeHelperDocument(raw []byte, v any) error {
	if len(raw) == 0 {
		return errors.New("sandbox: the helper message is empty")
	}
	limit := helperMessageLimit(v)
	if len(raw) > limit {
		return fmt.Errorf("sandbox: the helper message is larger than %d bytes", limit)
	}
	if err := validateHelperDocument(raw); err != nil {
		return err
	}
	return bindHelperDocument(raw, v)
}

// helperMessageLimit 在 JSON 解码剥离空白之前统一核整帧；旧协议保留原1MiB预算。
func helperMessageLimit(value any) int {
	switch value.(type) {
	case GenerationObserveRequest, *GenerationObserveRequest,
		GenerationStopRequest, *GenerationStopRequest,
		GenerationRetireRequest, *GenerationRetireRequest,
		GenerationObserveResponse, *GenerationObserveResponse,
		GenerationStopResponse, *GenerationStopResponse,
		GenerationRetireResponse, *GenerationRetireResponse:
		return MaxGenerationMessage
	default:
		return MaxHelperMessage
	}
}

// bindHelperDocument 仅绑定已扫描的正式结构；generation 共用它并先核精确 key。
func bindHelperDocument(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("sandbox: the helper message has invalid fields or types")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("sandbox: the helper message contains trailing data")
	}
	return nil
}
