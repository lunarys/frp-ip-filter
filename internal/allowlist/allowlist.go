// Package allowlist stores the IPs and prefixes allowed through the filter,
// with sliding TTLs and atomic persistence to a JSON file.
package allowlist

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrCapacityFull is returned by AddIP when the IP cap is reached and ip is not already present.
var ErrCapacityFull = errors.New("allowlist: capacity full")

type ipEntry struct {
	LastUpdated time.Time `json:"last_updated"`
}

type prefixEntry struct {
	Prefix      netip.Prefix `json:"prefix"`
	LastUpdated time.Time    `json:"last_updated"`
}

// allowlistFile is the on-disk shape, kept separate from List's in-memory
// maps since netip.Addr can't be a JSON object key.
type allowlistFile struct {
	IPs      map[string]ipEntry     `json:"ips"`
	Prefixes map[string]prefixEntry `json:"prefixes"`
}

// List tracks IPs and IPv6 prefixes permitted to reach the private
// listener. Entries use a sliding TTL: any add/update resets the clock, so
// ipTTL/prefixTTL can be reconfigured and apply retroactively to existing
// entries (expiry is derived from LastUpdated, never stored directly).
type List struct {
	mu        sync.Mutex
	ips       map[netip.Addr]ipEntry
	prefixes  map[string]prefixEntry // keyed by login identity, one entry each
	maxIPs    int
	ipTTL     time.Duration
	prefixTTL time.Duration
	path      string
}

// New creates a List persisted at path, loading any live entries already
// stored there. A missing file starts empty; a corrupt one is logged and
// also starts empty rather than failing startup.
func New(path string, maxIPs int, ipTTL, prefixTTL time.Duration) (*List, error) {
	a := &List{
		ips:       make(map[netip.Addr]ipEntry),
		prefixes:  make(map[string]prefixEntry),
		maxIPs:    maxIPs,
		ipTTL:     ipTTL,
		prefixTTL: prefixTTL,
		path:      path,
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read allowlist file: %w", err)
	}

	var file allowlistFile
	if err := json.Unmarshal(data, &file); err != nil {
		log.Printf("allowlist: corrupt persisted file at %s, starting empty: %v", path, err)
		return a, nil
	}

	now := time.Now()
	for ipStr, entry := range file.IPs {
		if now.Sub(entry.LastUpdated) > ipTTL {
			continue
		}
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			log.Printf("allowlist: skipping invalid stored IP %q: %v", ipStr, err)
			continue
		}
		a.ips[addr] = entry
	}
	for login, entry := range file.Prefixes {
		if now.Sub(entry.LastUpdated) > prefixTTL {
			continue
		}
		a.prefixes[login] = entry
	}

	return a, nil
}

// AddIP registers ip, refreshing its TTL if already present. It sweeps
// expired IPs first, so the cap check always reflects only live entries.
func (a *List) AddIP(ip netip.Addr) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	a.sweepIPsLocked(now)

	if _, exists := a.ips[ip]; !exists && len(a.ips) >= a.maxIPs {
		return ErrCapacityFull
	}

	a.ips[ip] = ipEntry{LastUpdated: now}

	return a.persistLocked()
}

// AddPrefix upserts the prefix for login, refreshing its TTL. No cap check:
// this is naturally bounded by the number of distinct logins.
func (a *List) AddPrefix(login string, prefix netip.Prefix) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	a.sweepPrefixesLocked(now)

	a.prefixes[login] = prefixEntry{Prefix: prefix, LastUpdated: now}

	return a.persistLocked()
}

// IsAllowed reports whether ip is covered by a live IP entry or a live
// prefix. It only touches entries it actually visits (no full sweep), since
// this is the hot path called on every incoming connection. When ip matches
// a prefix, it also returns the dyndns login that registered it; a plain
// registered IP has no associated login, so that case returns "".
func (a *List) IsAllowed(ip netip.Addr) (bool, string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()

	if entry, ok := a.ips[ip]; ok {
		if now.Sub(entry.LastUpdated) <= a.ipTTL {
			return true, ""
		}
		delete(a.ips, ip)
	}

	for login, entry := range a.prefixes {
		if now.Sub(entry.LastUpdated) > a.prefixTTL {
			delete(a.prefixes, login)
			continue
		}
		if entry.Prefix.Contains(ip) {
			return true, login
		}
	}

	return false, ""
}

func (a *List) sweepIPsLocked(now time.Time) {
	for ip, entry := range a.ips {
		if now.Sub(entry.LastUpdated) > a.ipTTL {
			delete(a.ips, ip)
		}
	}
}

func (a *List) sweepPrefixesLocked(now time.Time) {
	for login, entry := range a.prefixes {
		if now.Sub(entry.LastUpdated) > a.prefixTTL {
			delete(a.prefixes, login)
		}
	}
}

// persistLocked writes the current state to disk atomically (temp file +
// rename), so a crash mid-write never leaves a corrupt file in place.
// Caller must hold a.mu.
func (a *List) persistLocked() error {
	file := allowlistFile{
		IPs:      make(map[string]ipEntry, len(a.ips)),
		Prefixes: make(map[string]prefixEntry, len(a.prefixes)),
	}
	for ip, entry := range a.ips {
		file.IPs[ip.String()] = entry
	}
	for login, entry := range a.prefixes {
		file.Prefixes[login] = entry
	}

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal allowlist: %w", err)
	}

	dir := filepath.Dir(a.path)
	tmp, err := os.CreateTemp(dir, ".allowlist-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp allowlist file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp allowlist file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp allowlist file: %w", err)
	}

	if err := os.Rename(tmpName, a.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename allowlist file: %w", err)
	}

	return nil
}
