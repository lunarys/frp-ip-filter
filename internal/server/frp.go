package server

import (
	"encoding/json"
	"net"
	"net/http"
	"net/netip"

	"github.com/lunarys/frp-ip-filter/internal/frpplugin"
)

// maxPluginBodyBytes caps request bodies on the frps plugin hook. Real
// payloads are small JSON objects (proxy names, addresses, a metas map);
// this leaves generous headroom while preventing an oversized body from
// being decoded into memory.
const maxPluginBodyBytes = 64 * 1024

// frpPluginHandler implements the frps server-plugin HTTP hook. Non-200
// signals a plugin failure to frps, so malformed requests get a 4xx; an
// actual filtering decision is always a 200 with reject/unchange in the body.
func (s *Server) frpPluginHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxPluginBodyBytes)

	var req frpplugin.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	switch req.Op {
	case "Login":
		var content frpplugin.LoginContent
		if err := json.Unmarshal(req.Content, &content); err != nil {
			http.Error(w, "invalid content", http.StatusBadRequest)
			return
		}
		s.writePluginResponse(w, s.checkAddr("Login", content.ClientAddress, ""))

	case "NewProxy":
		var content frpplugin.NewProxyContent
		if err := json.Unmarshal(req.Content, &content); err != nil {
			http.Error(w, "invalid content", http.StatusBadRequest)
			return
		}
		s.proxyFilters.Set(content.ProxyName, content.Metas)
		s.logFrpDebug("op=NewProxy proxy=%s filter_enabled=%v", content.ProxyName, s.proxyFilters.IsEnabled(content.ProxyName))
		s.writePluginResponse(w, frpplugin.Response{Unchange: true})

	case "CloseProxy":
		var content frpplugin.CloseProxyContent
		if err := json.Unmarshal(req.Content, &content); err != nil {
			http.Error(w, "invalid content", http.StatusBadRequest)
			return
		}
		s.proxyFilters.Remove(content.ProxyName)
		s.writePluginResponse(w, frpplugin.Response{Unchange: true})

	case "NewUserConn":
		var content frpplugin.NewUserConnContent
		if err := json.Unmarshal(req.Content, &content); err != nil {
			http.Error(w, "invalid content", http.StatusBadRequest)
			return
		}
		if !s.proxyFilters.IsEnabled(content.ProxyName) {
			s.logFrpDebug("op=NewUserConn proxy=%s: filtering disabled for this proxy, allowing", content.ProxyName)
			s.writePluginResponse(w, frpplugin.Response{Unchange: true})
			return
		}
		s.writePluginResponse(w, s.checkAddr("NewUserConn", content.RemoteAddr, content.ProxyName))

	default:
		s.logFrpDebug("op=%s (unhandled, allowing unchanged)", req.Op)
		s.writePluginResponse(w, frpplugin.Response{Unchange: true})
	}
}

// checkAddr rejects unless addr's host is covered by the allowlist. addr may
// be "host:port" (as frp sends it) or a bare host. proxyName is logged when
// available (it's unknown at Login time, since no proxy is involved yet). On
// an allow, the dyndns login that registered the matching prefix is logged
// too, if the match came from a prefix rather than a plain registered IP -
// a rejection never has a login to show, since nothing matched.
func (s *Server) checkAddr(op, addr, proxyName string) frpplugin.Response {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ctx := proxyField(proxyName)

	ip, err := netip.ParseAddr(host)
	if err != nil {
		s.logFrpDebug("op=%s addr=%q%s: could not parse address", op, addr, ctx)
		return frpplugin.Response{Reject: true, RejectReason: "could not parse address"}
	}

	allowed, login := s.allowlist.IsAllowed(ip)
	if !allowed {
		s.logFrpDebug("op=%s ip=%s%s: rejected", op, ip, ctx)
		return frpplugin.Response{Reject: true, RejectReason: "IP not allowed"}
	}

	s.logFrpDebug("op=%s ip=%s%s: allowed%s", op, ip, ctx, loginSuffix(login))
	return frpplugin.Response{Unchange: true}
}

func proxyField(proxyName string) string {
	if proxyName == "" {
		return ""
	}
	return " proxy=" + proxyName
}

func loginSuffix(login string) string {
	if login == "" {
		return ""
	}
	return " (" + login + ")"
}

func (s *Server) writePluginResponse(w http.ResponseWriter, resp frpplugin.Response) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
