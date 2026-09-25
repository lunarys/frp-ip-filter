package server

import (
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lunarys/frp-ip-filter/internal/allowlist"
	"github.com/lunarys/frp-ip-filter/internal/auth"
	"github.com/lunarys/frp-ip-filter/internal/frpplugin"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	list, err := allowlist.New(filepath.Join(t.TempDir(), "allowlist.json"), 10, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return New(list, auth.New(nil, nil), Logging{})
}

func doPluginRequest(t *testing.T, s *Server, op string, content any) frpplugin.Response {
	t.Helper()

	body, err := json.Marshal(frpplugin.Request{
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

	var resp frpplugin.Response
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

	resp := doPluginRequest(t, s, "Login", frpplugin.LoginContent{ClientAddress: "10.0.0.1:54321"})

	if resp.Reject {
		t.Fatalf("expected allowed, got reject: %s", resp.RejectReason)
	}
	if !resp.Unchange {
		t.Fatal("expected unchange=true on allow")
	}
}

func TestFrpPluginLoginRejected(t *testing.T) {
	s := newTestServer(t)

	resp := doPluginRequest(t, s, "Login", frpplugin.LoginContent{ClientAddress: "10.0.0.99:54321"})

	if !resp.Reject {
		t.Fatal("expected reject for unlisted IP")
	}
}

func TestFrpPluginNewUserConnRejected(t *testing.T) {
	s := newTestServer(t)

	resp := doPluginRequest(t, s, "NewUserConn", frpplugin.NewUserConnContent{ProxyName: "web", RemoteAddr: "203.0.113.5:1234"})

	if !resp.Reject {
		t.Fatal("expected reject for unlisted visitor IP")
	}
}

func TestFrpPluginNewUserConnFilteredByDefault(t *testing.T) {
	s := newTestServer(t)

	// No NewProxy seen for "web" yet - opt-out policy means it's filtered by
	// default, so an unlisted visitor IP is still rejected.
	resp := doPluginRequest(t, s, "NewUserConn", frpplugin.NewUserConnContent{ProxyName: "web", RemoteAddr: "203.0.113.5:1234"})

	if !resp.Reject {
		t.Fatal("expected proxy with no known metadata to be filtered by default")
	}
}

func TestFrpPluginNewProxyOptsOutOfFiltering(t *testing.T) {
	s := newTestServer(t)

	newProxyResp := doPluginRequest(t, s, "NewProxy", frpplugin.NewProxyContent{
		ProxyName: "public-site",
		Metas:     map[string]string{"ip_filter": "false"},
	})
	if newProxyResp.Reject {
		t.Fatal("NewProxy should never be rejected by this plugin")
	}

	resp := doPluginRequest(t, s, "NewUserConn", frpplugin.NewUserConnContent{ProxyName: "public-site", RemoteAddr: "203.0.113.5:1234"})

	if resp.Reject {
		t.Fatal("expected proxy that opted out via metadata to allow unlisted visitor IPs")
	}
}

func TestFrpPluginCloseProxyResetsToFilteredByDefault(t *testing.T) {
	s := newTestServer(t)

	doPluginRequest(t, s, "NewProxy", frpplugin.NewProxyContent{
		ProxyName: "public-site",
		Metas:     map[string]string{"ip_filter": "false"},
	})
	doPluginRequest(t, s, "CloseProxy", frpplugin.CloseProxyContent{ProxyName: "public-site"})

	resp := doPluginRequest(t, s, "NewUserConn", frpplugin.NewUserConnContent{ProxyName: "public-site", RemoteAddr: "203.0.113.5:1234"})

	if !resp.Reject {
		t.Fatal("expected proxy to revert to filtered-by-default after CloseProxy")
	}
}

func TestFrpPluginHandlerRejectsOversizedBody(t *testing.T) {
	s := newTestServer(t)

	oversized := strings.Repeat("a", maxPluginBodyBytes+1)
	body := `{"version":"0.1.0","op":"Login","content":"` + oversized + `"}`

	req := httptest.NewRequest("POST", "/frp-plugin", strings.NewReader(body))
	rec := httptest.NewRecorder()

	s.frpPluginHandler(rec, req)

	if rec.Code != 400 {
		t.Fatalf("expected 400 for oversized body, got %d", rec.Code)
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
