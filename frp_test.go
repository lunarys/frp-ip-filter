package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T) *server {
	t.Helper()
	list, err := newAllowlist(filepath.Join(t.TempDir(), "allowlist.json"), 10, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &server{allowlist: list, auth: &authConfig{}, logging: &loggingConfig{}, proxyFilters: newProxyFilters()}
}

func doPluginRequest(t *testing.T, s *server, op string, content any) pluginResponse {
	t.Helper()

	body, err := json.Marshal(pluginRequest{
		Version: "0.1.0",
		Op:      op,
		Content: mustMarshal(t, content),
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/frp-plugin", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()

	s.frpPluginHandler(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp pluginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

func mustMarshal(t *testing.T, v any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestFrpPluginLoginAllowed(t *testing.T) {
	s := newTestServer(t)
	ip := netip.MustParseAddr("10.0.0.1")
	if err := s.allowlist.AddIP(ip); err != nil {
		t.Fatal(err)
	}

	resp := doPluginRequest(t, s, "Login", loginContent{ClientAddress: "10.0.0.1:54321"})

	if resp.Reject {
		t.Fatalf("expected allowed, got reject: %s", resp.RejectReason)
	}
	if !resp.Unchange {
		t.Fatal("expected unchange=true on allow")
	}
}

func TestFrpPluginLoginRejected(t *testing.T) {
	s := newTestServer(t)

	resp := doPluginRequest(t, s, "Login", loginContent{ClientAddress: "10.0.0.99:54321"})

	if !resp.Reject {
		t.Fatal("expected reject for unlisted IP")
	}
}

func TestFrpPluginNewUserConnRejected(t *testing.T) {
	s := newTestServer(t)

	resp := doPluginRequest(t, s, "NewUserConn", newUserConnContent{ProxyName: "web", RemoteAddr: "203.0.113.5:1234"})

	if !resp.Reject {
		t.Fatal("expected reject for unlisted visitor IP")
	}
}

func TestFrpPluginNewUserConnFilteredByDefault(t *testing.T) {
	s := newTestServer(t)

	// No NewProxy seen for "web" yet - opt-out policy means it's filtered by
	// default, so an unlisted visitor IP is still rejected.
	resp := doPluginRequest(t, s, "NewUserConn", newUserConnContent{ProxyName: "web", RemoteAddr: "203.0.113.5:1234"})

	if !resp.Reject {
		t.Fatal("expected proxy with no known metadata to be filtered by default")
	}
}

func TestFrpPluginNewProxyOptsOutOfFiltering(t *testing.T) {
	s := newTestServer(t)

	newProxyResp := doPluginRequest(t, s, "NewProxy", newProxyContent{
		ProxyName: "public-site",
		Metas:     map[string]string{"ip_filter": "false"},
	})
	if newProxyResp.Reject {
		t.Fatal("NewProxy should never be rejected by this plugin")
	}

	resp := doPluginRequest(t, s, "NewUserConn", newUserConnContent{ProxyName: "public-site", RemoteAddr: "203.0.113.5:1234"})

	if resp.Reject {
		t.Fatal("expected proxy that opted out via metadata to allow unlisted visitor IPs")
	}
}

func TestFrpPluginCloseProxyResetsToFilteredByDefault(t *testing.T) {
	s := newTestServer(t)

	doPluginRequest(t, s, "NewProxy", newProxyContent{
		ProxyName: "public-site",
		Metas:     map[string]string{"ip_filter": "false"},
	})
	doPluginRequest(t, s, "CloseProxy", closeProxyContent{ProxyName: "public-site"})

	resp := doPluginRequest(t, s, "NewUserConn", newUserConnContent{ProxyName: "public-site", RemoteAddr: "203.0.113.5:1234"})

	if !resp.Reject {
		t.Fatal("expected proxy to revert to filtered-by-default after CloseProxy")
	}
}

func TestFrpPluginUnhandledOpAllowsUnchanged(t *testing.T) {
	s := newTestServer(t)

	resp := doPluginRequest(t, s, "Ping", map[string]any{})

	if resp.Reject {
		t.Fatal("expected unhandled op to pass through unchanged, not reject")
	}
	if !resp.Unchange {
		t.Fatal("expected unchange=true for unhandled op")
	}
}
