package main

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
)

type server struct {
	allowlist    *allowlist
	auth         *authConfig
	logging      *loggingConfig
	proxyFilters *proxyFilters
}

func (s *server) registerClient(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if !s.auth.validateToken(token) {
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
		if errors.Is(err, ErrCapacityFull) {
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

func (s *server) registerClientPrefix(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok || !s.auth.validateLogin(username, password) {
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

func (s *server) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("OK"))
}
