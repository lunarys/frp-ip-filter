package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
)

// pluginRequest/pluginResponse mirror frp's server plugin HTTP protocol
// (pkg/plugin/server/types.go in fatedier/frp). Content is polymorphic
// depending on Op, so it's decoded lazily per case.
type pluginRequest struct {
	Version string          `json:"version"`
	Op      string          `json:"op"`
	Content json.RawMessage `json:"content"`
}

type pluginResponse struct {
	Reject       bool   `json:"reject"`
	RejectReason string `json:"reject_reason"`
	Unchange     bool   `json:"unchange"`
	Content      any    `json:"content"`
}

type loginContent struct {
	ClientAddress string `json:"client_address"`
}

type newProxyContent struct {
	ProxyName string            `json:"proxy_name"`
	Metas     map[string]string `json:"metas"`
}

type closeProxyContent struct {
	ProxyName string `json:"proxy_name"`
}

type newUserConnContent struct {
	ProxyName  string `json:"proxy_name"`
	RemoteAddr string `json:"remote_addr"`
}

// proxyFilters remembers, per proxy_name, whether IP filtering is enabled -
// learned from the "ip_filter" metadata on that proxy's "NewProxy" event and
// cleared on "CloseProxy". Filtering is opt-out: a proxy filters unless its
// metadata explicitly disables it (also the default for a proxy this
// instance hasn't seen a NewProxy for, e.g. right after a restart).
type proxyFilters struct {
	mu      sync.Mutex
	enabled map[string]bool
}

func newProxyFilters() *proxyFilters {
	return &proxyFilters{enabled: make(map[string]bool)}
}

func (p *proxyFilters) set(proxyName string, metas map[string]string) {
	enabled := true
	if v, ok := metas["ip_filter"]; ok {
		if parsed, err := strconv.ParseBool(v); err == nil {
			enabled = parsed
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled[proxyName] = enabled
}

func (p *proxyFilters) remove(proxyName string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.enabled, proxyName)
}

func (p *proxyFilters) isEnabled(proxyName string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	enabled, ok := p.enabled[proxyName]
	if !ok {
		return true
	}
	return enabled
}

// maxPluginBodyBytes caps request bodies on the frps plugin hook. Real
// payloads are small JSON objects (proxy names, addresses, a metas map);
// this leaves generous headroom while preventing an oversized body from
// being decoded into memory.
const maxPluginBodyBytes = 64 * 1024

// frpPluginHandler implements the frps server-plugin HTTP hook. Non-200
// signals a plugin failure to frps, so malformed requests get a 4xx; an
// actual filtering decision is always a 200 with reject/unchange in the body.
func (s *server) frpPluginHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxPluginBodyBytes)

	var req pluginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	switch req.Op {
	case "Login":
		var content loginContent
		if err := json.Unmarshal(req.Content, &content); err != nil {
			http.Error(w, "invalid content", http.StatusBadRequest)
			return
		}
		s.writePluginResponse(w, s.checkAddr("Login", content.ClientAddress, ""))

	case "NewProxy":
		var content newProxyContent
		if err := json.Unmarshal(req.Content, &content); err != nil {
			http.Error(w, "invalid content", http.StatusBadRequest)
			return
		}
		s.proxyFilters.set(content.ProxyName, content.Metas)
		s.logFrpDebug("op=NewProxy proxy=%s filter_enabled=%v", content.ProxyName, s.proxyFilters.isEnabled(content.ProxyName))
		s.writePluginResponse(w, pluginResponse{Unchange: true})

	case "CloseProxy":
		var content closeProxyContent
		if err := json.Unmarshal(req.Content, &content); err != nil {
			http.Error(w, "invalid content", http.StatusBadRequest)
			return
		}
		s.proxyFilters.remove(content.ProxyName)
		s.writePluginResponse(w, pluginResponse{Unchange: true})

	case "NewUserConn":
		var content newUserConnContent
		if err := json.Unmarshal(req.Content, &content); err != nil {
			http.Error(w, "invalid content", http.StatusBadRequest)
			return
		}
		if !s.proxyFilters.isEnabled(content.ProxyName) {
			s.logFrpDebug("op=NewUserConn proxy=%s: filtering disabled for this proxy, allowing", content.ProxyName)
			s.writePluginResponse(w, pluginResponse{Unchange: true})
			return
		}
		s.writePluginResponse(w, s.checkAddr("NewUserConn", content.RemoteAddr, content.ProxyName))

	default:
		s.logFrpDebug("op=%s (unhandled, allowing unchanged)", req.Op)
		s.writePluginResponse(w, pluginResponse{Unchange: true})
	}
}

// checkAddr rejects unless addr's host is covered by the allowlist. addr may
// be "host:port" (as frp sends it) or a bare host. proxyName is logged when
// available (it's unknown at Login time, since no proxy is involved yet). On
// an allow, the dyndns login that registered the matching prefix is logged
// too, if the match came from a prefix rather than a plain registered IP -
// a rejection never has a login to show, since nothing matched.
func (s *server) checkAddr(op, addr, proxyName string) pluginResponse {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ctx := proxyField(proxyName)

	ip, err := netip.ParseAddr(host)
	if err != nil {
		s.logFrpDebug("op=%s addr=%q%s: could not parse address", op, addr, ctx)
		return pluginResponse{Reject: true, RejectReason: "could not parse address"}
	}

	allowed, login := s.allowlist.IsAllowed(ip)
	if !allowed {
		s.logFrpDebug("op=%s ip=%s%s: rejected", op, ip, ctx)
		return pluginResponse{Reject: true, RejectReason: "IP not allowed"}
	}

	s.logFrpDebug("op=%s ip=%s%s: allowed%s", op, ip, ctx, loginSuffix(login))
	return pluginResponse{Unchange: true}
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

func (s *server) writePluginResponse(w http.ResponseWriter, resp pluginResponse) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
