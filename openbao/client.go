// Package openbao is a small OpenBao (or HashiCorp Vault ≤ 1.14) HTTP
// client implementing exactly what the fleet pairing companion needs:
//
//   - AppRole login (auth/approle/login)
//   - KV v2 read / write / destroy under secret/data/<path>
//
// It deliberately avoids the upstream Vault Go SDK (huge, with many
// dependencies, and not gomobile-bind-friendly) — the surface here is
// stdlib net/http + encoding/json. That makes the resulting AAR tiny
// and the JVM-side surface trivial.
package openbao

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config holds construction parameters for [New].
type Config struct {
	// BaseURL is the OpenBao server URL, e.g. https://bao.internal:8200.
	BaseURL string
	// RoleID is the AppRole role identifier (semi-public).
	RoleID string
	// SecretID is the AppRole secret identifier (per-machine secret).
	SecretID string
	// HTTPClient is optional; defaults to a 5 s-timeout client.
	HTTPClient *http.Client
}

// Client talks to OpenBao using AppRole auth and the KV v2 secrets
// engine mounted at /secret. Implementations are safe for concurrent
// use; [Login] is called automatically before any KV op when no token
// is cached or the cached one is close to expiry.
type Client interface {
	// Login authenticates with the configured AppRole and caches the
	// resulting token. Subsequent KV calls reuse the cache.
	Login(ctx context.Context) error

	// PutSecret writes data into secret/data/<path>. Existing data is
	// overwritten.
	PutSecret(ctx context.Context, path string, data map[string]string) error

	// GetSecret reads secret/data/<path>. Returns the inner data map
	// or an error if the path doesn't exist.
	GetSecret(ctx context.Context, path string) (map[string]string, error)

	// DestroySecret marks every version under secret/data/<path> as
	// destroyed and removes the metadata entry.
	DestroySecret(ctx context.Context, path string) error
}

// New constructs a Client. The returned Client lazily logs in on the
// first Put/Get/Destroy call.
func New(cfg Config) (Client, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("openbao: BaseURL is required")
	}
	if cfg.RoleID == "" || cfg.SecretID == "" {
		return nil, errors.New("openbao: RoleID and SecretID are required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	return &client{
		baseURL:  strings.TrimRight(cfg.BaseURL, "/"),
		roleID:   cfg.RoleID,
		secretID: cfg.SecretID,
		hc:       hc,
	}, nil
}

const (
	// kvMount is the KV v2 mount path the runbook configures by default.
	kvMount = "secret"
	// refreshAheadSeconds is how close to expiry we proactively re-login.
	refreshAheadSeconds = 60
)

type client struct {
	baseURL  string
	roleID   string
	secretID string
	hc       *http.Client

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

// loginRequest / loginResponse model the JSON shapes of POST /v1/auth/approle/login.
type loginRequest struct {
	RoleID   string `json:"role_id"`
	SecretID string `json:"secret_id"`
}

type loginResponse struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
	} `json:"auth"`
}

func (c *client) Login(ctx context.Context) error {
	body, err := json.Marshal(loginRequest{RoleID: c.roleID, SecretID: c.secretID})
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodPost, "/v1/auth/approle/login", "", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("openbao: read login response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("openbao: AppRole login HTTP %d: %s", resp.StatusCode, raw)
	}
	var lr loginResponse
	if err := json.Unmarshal(raw, &lr); err != nil {
		return fmt.Errorf("openbao: decode login response: %w", err)
	}
	if lr.Auth.ClientToken == "" {
		return errors.New("openbao: login response missing client_token")
	}
	lease := lr.Auth.LeaseDuration
	if lease <= 0 {
		lease = 4 * 3600 // 4 hours, matching the runbook's recommended TTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = lr.Auth.ClientToken
	c.tokenExpiry = time.Now().Add(time.Duration(lease) * time.Second)
	return nil
}

// kvWriteRequest / kvReadResponse / kvDestroyRequest model KV v2 shapes.
type kvWriteRequest struct {
	Data map[string]string `json:"data"`
}

type kvReadResponse struct {
	Data struct {
		Data map[string]string `json:"data"`
	} `json:"data"`
}

type kvDestroyRequest struct {
	Versions []int `json:"versions"`
}

func (c *client) PutSecret(ctx context.Context, path string, data map[string]string) error {
	if path == "" {
		return errors.New("openbao: empty path")
	}
	body, err := json.Marshal(kvWriteRequest{Data: data})
	if err != nil {
		return err
	}
	if err := c.ensureToken(ctx); err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodPost, "/v1/"+kvMount+"/data/"+path, c.cachedToken(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.statusError(resp, "PutSecret "+path)
	}
	return nil
}

func (c *client) GetSecret(ctx context.Context, path string) (map[string]string, error) {
	if path == "" {
		return nil, errors.New("openbao: empty path")
	}
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, http.MethodGet, "/v1/"+kvMount+"/data/"+path, c.cachedToken(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("openbao: %s not found", path)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.statusError(resp, "GetSecret "+path)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("openbao: read GetSecret body: %w", err)
	}
	var rr kvReadResponse
	if err := json.Unmarshal(raw, &rr); err != nil {
		return nil, fmt.Errorf("openbao: decode KV response: %w", err)
	}
	return rr.Data.Data, nil
}

func (c *client) DestroySecret(ctx context.Context, path string) error {
	if path == "" {
		return errors.New("openbao: empty path")
	}
	if err := c.ensureToken(ctx); err != nil {
		return err
	}
	// First wipe all versions, then delete metadata so the path is fully
	// purged. Any 404 along the way is fine — the goal is end-state.
	versions := []int{}
	for v := 1; v <= 32; v++ {
		versions = append(versions, v)
	}
	body, err := json.Marshal(kvDestroyRequest{Versions: versions})
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodPost, "/v1/"+kvMount+"/destroy/"+path, c.cachedToken(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()

	resp2, err := c.do(ctx, http.MethodDelete, "/v1/"+kvMount+"/metadata/"+path, c.cachedToken(), nil)
	if err != nil {
		return err
	}
	resp2.Body.Close()
	return nil
}

func (c *client) ensureToken(ctx context.Context) error {
	c.mu.Lock()
	stale := c.token == "" ||
		time.Until(c.tokenExpiry) < refreshAheadSeconds*time.Second
	c.mu.Unlock()
	if !stale {
		return nil
	}
	return c.Login(ctx)
}

func (c *client) cachedToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

func (c *client) do(ctx context.Context, method, path, token string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("openbao: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openbao: %s %s: %w", method, path, err)
	}
	return resp, nil
}

func (c *client) statusError(resp *http.Response, what string) error {
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("openbao: %s HTTP %d: %s", what, resp.StatusCode, body)
}
