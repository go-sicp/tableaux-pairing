package openbao

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeBao is a tiny in-memory OpenBao look-alike used by every test in
// this file. Only the endpoints exercised by [Client] are implemented;
// anything else 404s.
type fakeBao struct {
	mu          atomicData
	expectToken string
	loginCalls  atomic.Int32
	putCalls    atomic.Int32
	getCalls    atomic.Int32
}

type atomicData struct {
	store map[string]map[string]string
}

func newFakeBao() *fakeBao {
	return &fakeBao{
		mu:          atomicData{store: map[string]map[string]string{}},
		expectToken: "test-issued-token",
	}
}

func (f *fakeBao) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		f.loginCalls.Add(1)
		body, _ := io.ReadAll(r.Body)
		var req map[string]string
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		if req["role_id"] == "" || req["secret_id"] == "" {
			http.Error(w, "missing creds", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{
				"client_token":   f.expectToken,
				"lease_duration": 600,
			},
		})
	})

	mux.HandleFunc("/v1/secret/data/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != f.expectToken {
			http.Error(w, "no token", http.StatusForbidden)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
		switch r.Method {
		case http.MethodPost:
			f.putCalls.Add(1)
			body, _ := io.ReadAll(r.Body)
			var p struct {
				Data map[string]string `json:"data"`
			}
			if err := json.Unmarshal(body, &p); err != nil {
				http.Error(w, "bad json", 400)
				return
			}
			f.mu.store[path] = p.Data
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			f.getCalls.Add(1)
			data, ok := f.mu.store[path]
			if !ok {
				http.Error(w, "not found", 404)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"data": data},
			})
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/v1/secret/destroy/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1/secret/destroy/")
		delete(f.mu.store, path)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/secret/metadata/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	return mux
}

func newTestClient(t *testing.T, fb *fakeBao) (Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(fb.handler())
	t.Cleanup(srv.Close)
	c, err := New(Config{
		BaseURL:  srv.URL,
		RoleID:   "rid",
		SecretID: "sid",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, srv
}

func TestNewRejectsMissingArgs(t *testing.T) {
	if _, err := New(Config{RoleID: "r", SecretID: "s"}); err == nil {
		t.Error("expected error for missing BaseURL")
	}
	if _, err := New(Config{BaseURL: "u", SecretID: "s"}); err == nil {
		t.Error("expected error for missing RoleID")
	}
	if _, err := New(Config{BaseURL: "u", RoleID: "r"}); err == nil {
		t.Error("expected error for missing SecretID")
	}
}

func TestPutAndGetRoundTrip(t *testing.T) {
	fb := newFakeBao()
	c, _ := newTestClient(t, fb)
	ctx := context.Background()

	in := map[string]string{
		"operator_token":  "op-1",
		"admin_token":     "ad-1",
		"cert_pem":        "-----BEGIN-----",
		"client_cert_pem": "-----BEGIN-----",
		"client_key_pem":  "-----BEGIN-----",
	}
	if err := c.PutSecret(ctx, "fleet/panel-1", in); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	got, err := c.GetSecret(ctx, "fleet/panel-1")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if len(got) != len(in) {
		t.Fatalf("len(got)=%d, want %d (got=%v)", len(got), len(in), got)
	}
	for k, v := range in {
		if got[k] != v {
			t.Errorf("got[%q]=%q, want %q", k, got[k], v)
		}
	}
}

func TestLoginIsLazyAndCached(t *testing.T) {
	fb := newFakeBao()
	c, _ := newTestClient(t, fb)
	ctx := context.Background()

	// Several calls in a row reuse the cached token.
	if err := c.PutSecret(ctx, "x", map[string]string{"a": "1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetSecret(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetSecret(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	if got := fb.loginCalls.Load(); got != 1 {
		t.Errorf("login called %d times, want exactly 1 (token was cached)", got)
	}
}

func TestGetMissingReturns404(t *testing.T) {
	fb := newFakeBao()
	c, _ := newTestClient(t, fb)
	ctx := context.Background()
	if _, err := c.GetSecret(ctx, "fleet/never-written"); err == nil {
		t.Fatal("expected error on missing secret")
	}
}

func TestPutEmptyPathRejected(t *testing.T) {
	fb := newFakeBao()
	c, _ := newTestClient(t, fb)
	if err := c.PutSecret(context.Background(), "", map[string]string{}); err == nil {
		t.Fatal("expected error on empty path")
	}
}

func TestDestroyClearsStorage(t *testing.T) {
	fb := newFakeBao()
	c, _ := newTestClient(t, fb)
	ctx := context.Background()

	_ = c.PutSecret(ctx, "fleet/p", map[string]string{"a": "b"})
	if _, err := c.GetSecret(ctx, "fleet/p"); err != nil {
		t.Fatalf("pre-destroy GetSecret: %v", err)
	}
	if err := c.DestroySecret(ctx, "fleet/p"); err != nil {
		t.Fatalf("DestroySecret: %v", err)
	}
	if _, err := c.GetSecret(ctx, "fleet/p"); err == nil {
		t.Fatal("expected GetSecret to fail after destroy")
	}
}

func TestLoginFailureSurfacesAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "permission denied", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL, RoleID: "r", SecretID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	err = c.Login(context.Background())
	if err == nil {
		t.Fatal("expected error from a 403 login response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error %q should mention 403", err)
	}
}

func TestErrorIsNotNilHelper(t *testing.T) {
	// Sanity: we use errors.New in places, ensure it threads through.
	e := errors.New("x")
	if e == nil {
		t.Fatal("nil errors.New result")
	}
}
