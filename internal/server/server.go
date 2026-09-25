// Package server implements the HTTP endpoints: the public unlock/dyndns
// registration handlers and the private frps plugin hook.
package server

import (
	"errors"
	"net"
	"net/http"
	"net/netip"

	"github.com/lunarys/frp-ip-filter/internal/allowlist"
	"github.com/lunarys/frp-ip-filter/internal/auth"
	"github.com/lunarys/frp-ip-filter/internal/frpplugin"
)

// Logging toggles the optional log streams.
type Logging struct {
	AccessLog bool // registration attempts on the public endpoints
	FrpDebug  bool // every frps plugin decision
}

type Server struct {
	allowlist    *allowlist.List
	auth         *auth.Authenticator
	logging      Logging
	proxyFilters *frpplugin.ProxyFilters
}

func New(list *allowlist.List, authn *auth.Authenticator, logging Logging) *Server {
	return &Server{
		allowlist:    list,
		auth:         authn,
		logging:      logging,
		proxyFilters: frpplugin.NewProxyFilters(),
	}
}

// PublicHandler serves the endpoints clients call to register themselves.
// It is meant to be reachable from the internet.
func (s *Server) PublicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /unlock", s.registerClient)
	mux.HandleFunc("GET /dyndns", s.registerClientPrefix)
	return mux
}

// PrivateHandler serves the frps plugin hook and health check. It must only
// be reachable by frps, since the plugin hook is unauthenticated.
func (s *Server) PrivateHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /frp-plugin", s.frpPluginHandler)
	mux.HandleFunc("GET /healthz", s.healthCheck)
	return mux
}

func (s *Server) registerClient(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if !s.auth.ValidateToken(token) {
		s.logAccess("unlock rejected: invalid token, remote=%s", r.RemoteAddr)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		s.logAccess("unlock rejected: could not parse remote addr %q", r.RemoteAddr)
		http.Error(w, "could not determine client IP", http.StatusInternalServerError)
		return
	}

	if err := s.allowlist.AddIP(ip); err != nil {
		if errors.Is(err, allowlist.ErrCapacityFull) {
			s.logAccess("unlock rejected: capacity full, ip=%s", ip)
			http.Error(w, "allowlist full, try again later", http.StatusServiceUnavailable)
			return
		}
		s.logAccess("unlock error: ip=%s err=%v", ip, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.logAccess("unlock: added ip=%s", ip)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("IP registered successfully"))
}

func (s *Server) registerClientPrefix(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok || !s.auth.ValidateLogin(username, password) {
		s.logAccess("dyndns rejected: invalid credentials, remote=%s", r.RemoteAddr)
		w.Header().Set("WWW-Authenticate", `Basic realm="dyndns"`)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	prefix, err := netip.ParsePrefix(r.URL.Query().Get("prefix"))
	if err != nil {
		s.logAccess("dyndns rejected: invalid prefix, login=%s", username)
		http.Error(w, "invalid or missing prefix", http.StatusBadRequest)
		return
	}

	if err := s.allowlist.AddPrefix(username, prefix); err != nil {
		s.logAccess("dyndns error: login=%s err=%v", username, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.logAccess("dyndns: added prefix=%s login=%s", prefix, username)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("prefix registered successfully"))
}

func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("OK"))
}
