// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/actor"
	"github.com/qwq-panel/qwq/internal/authz"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/storage"
)

func runPlugin(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "bootstrap" {
		fmt.Fprintln(stderr, "usage: sudo qwq plugin bootstrap [--config FILE] [--timeout 3m] <pkg1.qwqpkg> [pkg2.qwqpkg ...]")
		return 2
	}
	return runPluginBootstrap(args[1:], stdout, stderr, defaultBootstrapSessionFactory)
}

type bootstrapSession struct {
	Client     *http.Client
	BaseURL    string
	HostHeader string
	Token      string
	Close      func()
}

type bootstrapSessionFactory func(ctx context.Context, cfgPath string, stderr io.Writer) (*bootstrapSession, error)

func defaultBootstrapSessionFactory(ctx context.Context, cfgPath string, stderr io.Writer) (*bootstrapSession, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn})).
		With("service", "plugin-bootstrap")
	local, closeDB, err := openLocalDatabase(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}
	az, err := authz.New(authz.Options{
		DB:         local.DB,
		Clock:      local.Clock,
		Logger:     logger,
		Principals: local.Identity,
	})
	if err != nil {
		closeDB()
		return nil, fmt.Errorf("init authorizer: %w", err)
	}

	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		closeDB()
		return nil, err
	}
	saName := "sys-bootstrap-" + hex.EncodeToString(rnd[:])
	bootActor := actor.Actor{
		Kind:      actor.Human,
		ID:        "sys_bootstrap",
		SessionID: "sess_bootstrap",
	}
	var created authz.CreatedServiceAccount
	err = local.DB.Update(ctx, func(tx *storage.Tx) error {
		var cerr error
		created, cerr = az.CreateServiceAccount(ctx, tx, authz.CreateServiceAccountInput{
			Actor: bootActor,
			Name:  saName,
			Role:  authz.RoleAdmin,
		})
		return cerr
	})
	if err != nil {
		closeDB()
		return nil, fmt.Errorf("mint temporary bootstrap credential: %w", err)
	}

	cleanup := func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = local.DB.Update(cleanCtx, func(tx *storage.Tx) error {
			return az.RevokeServiceAccount(cleanCtx, tx, authz.RevokeServiceAccountInput{
				Actor:            bootActor,
				ServiceAccountID: created.ID,
				ExpectedRevision: created.Revision,
			})
		})
		closeDB()
	}

	client, baseURL, hostHeader, err := buildLocalControllerClient(cfg)
	if err != nil {
		cleanup()
		return nil, err
	}
	return &bootstrapSession{
		Client:     client,
		BaseURL:    baseURL,
		HostHeader: hostHeader,
		Token:      created.Token,
		Close:      cleanup,
	}, nil
}

func buildLocalControllerClient(cfg config.Config) (*http.Client, string, string, error) {
	dialAddr := loopbackAddr(cfg.HTTP.Listen)
	hostHeader := ""
	serverName := "localhost"
	if len(cfg.HTTP.PublicOrigins) > 0 {
		if u, err := url.Parse(cfg.HTTP.PublicOrigins[0]); err == nil && u.Host != "" {
			hostHeader = u.Host
			if h, _, splitErr := net.SplitHostPort(u.Host); splitErr == nil && h != "" {
				serverName = h
			} else {
				serverName = u.Host
			}
		}
	} else if h, _, err := net.SplitHostPort(dialAddr); err == nil && h != "" {
		serverName = h
	}

	scheme := "https"
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, dialAddr)
		},
	}
	switch cfg.HTTP.TLS.Mode {
	case config.TLSProxy:
		scheme = "http"
	case config.TLSSelfSigned:
		certPath := filepath.Join(cfg.DataDir, "tls", "self_signed.crt")
		pemBytes, err := os.ReadFile(certPath)
		if err != nil {
			return nil, "", "", fmt.Errorf("read self-signed certificate %s: %w", certPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, "", "", fmt.Errorf("invalid PEM in %s", certPath)
		}
		tr.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
			ServerName: serverName,
		}
	case config.TLSACME:
		if len(cfg.HTTP.TLS.Domains) > 0 {
			serverName = cfg.HTTP.TLS.Domains[0]
		}
		tr.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: serverName,
		}
	default:
		return nil, "", "", fmt.Errorf("unsupported TLS mode %q", cfg.HTTP.TLS.Mode)
	}
	return &http.Client{Transport: tr}, scheme + "://" + dialAddr, hostHeader, nil
}

func loopbackAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func runPluginBootstrap(args []string, stdout, stderr io.Writer, openSession bootstrapSessionFactory) int {
	fs := flag.NewFlagSet("qwq plugin bootstrap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultPath, "bootstrap configuration file")
	timeout := fs.Duration("timeout", 3*time.Minute, "overall bootstrap timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	pkgPaths := fs.Args()
	if len(pkgPaths) == 0 {
		fmt.Fprintln(stderr, "usage: sudo qwq plugin bootstrap [--config FILE] [--timeout 3m] <pkg1.qwqpkg> [pkg2.qwqpkg ...]")
		return 2
	}
	for _, p := range pkgPaths {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() || st.Size() == 0 {
			fmt.Fprintf(stderr, "qwq plugin bootstrap: invalid package file %q\n", p)
			return 1
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	sess, err := openSession(ctx, *cfgPath, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "qwq plugin bootstrap: %v\n", err)
		return 1
	}
	defer sess.Close()

	for _, pkgPath := range pkgPaths {
		pid, ver, action, err := bootstrapSinglePackage(ctx, sess, pkgPath)
		if err != nil {
			fmt.Fprintf(stderr, "qwq plugin bootstrap: %s: %v\n", pkgPath, err)
			return 1
		}
		fmt.Fprintf(stdout, "==> 插件 %-18s v%-10s [%s]\n", pid, ver, action)
	}
	return 0
}

type bootstrapUploadResp struct {
	UploadID string `json:"upload_id"`
}

type bootstrapCapDTO struct {
	Name  string `json:"name"`
	Scope string `json:"scope,omitempty"`
}

type bootstrapInspectionResp struct {
	UploadID  string `json:"upload_id"`
	Signature struct {
		Valid   bool   `json:"valid"`
		Trusted bool   `json:"trusted"`
		KeyID   string `json:"key_id"`
	} `json:"signature"`
	Manifest *struct {
		ID           string            `json:"id"`
		Version      string            `json:"version"`
		Capabilities []bootstrapCapDTO `json:"capabilities"`
	} `json:"manifest"`
	Compatibility struct {
		OK       bool `json:"ok"`
		Problems []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"problems"`
	} `json:"compatibility"`
	Installed *struct {
		Version  string `json:"version"`
		Revision string `json:"revision"`
	} `json:"installed"`
}

func bootstrapSinglePackage(ctx context.Context, sess *bootstrapSession, pkgPath string) (string, string, string, error) {
	uploadID, err := uploadBootstrapPackage(ctx, sess, pkgPath)
	if err != nil {
		return "", "", "", err
	}
	var insp bootstrapInspectionResp
	if err := doBootstrapJSON(ctx, sess, http.MethodGet, "/api/v1/plugin-packages/"+url.PathEscape(uploadID), "", nil, http.StatusOK, &insp); err != nil {
		return "", "", "", fmt.Errorf("inspect package: %w", err)
	}
	if !insp.Signature.Valid || !insp.Signature.Trusted {
		return "", "", "", fmt.Errorf("package signature verification failed (valid=%v trusted=%v key_id=%s)",
			insp.Signature.Valid, insp.Signature.Trusted, insp.Signature.KeyID)
	}
	if insp.Manifest == nil || insp.Manifest.ID == "" || insp.Manifest.Version == "" {
		return "", "", "", fmt.Errorf("package manifest missing id or version")
	}
	if !insp.Compatibility.OK {
		var msgs []string
		for _, p := range insp.Compatibility.Problems {
			msgs = append(msgs, p.Code+": "+p.Message)
		}
		return "", "", "", fmt.Errorf("compatibility preflight failed: %s", strings.Join(msgs, "; "))
	}

	pid := insp.Manifest.ID
	ver := insp.Manifest.Version
	if insp.Installed != nil && insp.Installed.Version == ver {
		return pid, ver, "noop_already_active", nil
	}

	caps := insp.Manifest.Capabilities
	if caps == nil {
		caps = []bootstrapCapDTO{}
	}

	idemKey, err := randomIdempotencyKey()
	if err != nil {
		return "", "", "", err
	}

	if insp.Installed == nil {
		reqBody := map[string]any{
			"upload_id":             uploadID,
			"accepted_capabilities": caps,
		}
		if err := doBootstrapJSON(ctx, sess, http.MethodPost, "/api/v1/plugins", idemKey, reqBody, http.StatusCreated, nil); err != nil {
			return "", "", "", fmt.Errorf("install %s: %w", pid, err)
		}
		return pid, ver, "installed", nil
	}

	reqBody := map[string]any{
		"upload_id":             uploadID,
		"accepted_capabilities": caps,
		"expected_revision":     insp.Installed.Revision,
	}
	if err := doBootstrapJSON(ctx, sess, http.MethodPost, "/api/v1/plugins/"+url.PathEscape(pid)+"/update", idemKey, reqBody, http.StatusOK, nil); err != nil {
		return "", "", "", fmt.Errorf("update %s: %w", pid, err)
	}
	return pid, ver, "updated", nil
}

func uploadBootstrapPackage(ctx context.Context, sess *bootstrapSession, pkgPath string) (string, error) {
	f, err := os.Open(pkgPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("package", filepath.Base(pkgPath))
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(part, f); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sess.BaseURL+"/api/v1/plugin-packages", &body)
	if err != nil {
		return "", err
	}
	if sess.HostHeader != "" {
		req.Host = sess.HostHeader
	}
	req.Header.Set("Authorization", "Bearer "+sess.Token)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := sess.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("upload status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out bootstrapUploadResp
	if err := json.Unmarshal(raw, &out); err != nil || out.UploadID == "" {
		return "", fmt.Errorf("invalid upload response")
	}
	return out.UploadID, nil
}

func doBootstrapJSON(ctx context.Context, sess *bootstrapSession, method, path, idemKey string, reqObj any, wantStatus int, out any) error {
	var bodyReader io.Reader
	if reqObj != nil {
		raw, err := json.Marshal(reqObj)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, sess.BaseURL+path, bodyReader)
	if err != nil {
		return err
	}
	if sess.HostHeader != "" {
		req.Host = sess.HostHeader
	}
	req.Header.Set("Authorization", "Bearer "+sess.Token)
	if reqObj != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	resp, err := sess.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode != wantStatus {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func randomIdempotencyKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "boot-" + hex.EncodeToString(b[:]), nil
}
