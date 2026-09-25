// Package frpplugin models frp's server plugin HTTP protocol and tracks
// which proxies have IP filtering enabled.
package frpplugin

import (
	"encoding/json"
	"strconv"
	"sync"
)

// Request/Response mirror frp's server plugin HTTP protocol
// (pkg/plugin/server/types.go in fatedier/frp). Content is polymorphic
// depending on Op, so it's decoded lazily per case.
type Request struct {
	Version string          `json:"version"`
	Op      string          `json:"op"`
	Content json.RawMessage `json:"content"`
}

type Response struct {
	Reject       bool   `json:"reject"`
	RejectReason string `json:"reject_reason"`
	Unchange     bool   `json:"unchange"`
	Content      any    `json:"content"`
}

type LoginContent struct {
	ClientAddress string `json:"client_address"`
}

type NewProxyContent struct {
	ProxyName string            `json:"proxy_name"`
	Metas     map[string]string `json:"metas"`
}

type CloseProxyContent struct {
	ProxyName string `json:"proxy_name"`
}

type NewUserConnContent struct {
	ProxyName  string `json:"proxy_name"`
	RemoteAddr string `json:"remote_addr"`
}

// ProxyFilters remembers, per proxy_name, whether IP filtering is enabled -
// learned from the "ip_filter" metadata on that proxy's "NewProxy" event and
// cleared on "CloseProxy". Filtering is opt-out: a proxy filters unless its
// metadata explicitly disables it (also the default for a proxy this
// instance hasn't seen a NewProxy for, e.g. right after a restart).
type ProxyFilters struct {
	mu      sync.Mutex
	enabled map[string]bool
}

func NewProxyFilters() *ProxyFilters {
	return &ProxyFilters{enabled: make(map[string]bool)}
}

func (p *ProxyFilters) Set(proxyName string, metas map[string]string) {
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

func (p *ProxyFilters) Remove(proxyName string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.enabled, proxyName)
}

func (p *ProxyFilters) IsEnabled(proxyName string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	enabled, ok := p.enabled[proxyName]
	if !ok {
		return true
	}
	return enabled
}
