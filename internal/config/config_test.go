package config

import (
	"testing"
	"time"
)

func TestLoadAllowlistConfigDefaults(t *testing.T) {
	cfg, err := loadAllowlist()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Path != "allowlist.json" {
		t.Errorf("path = %q, want %q", cfg.Path, "allowlist.json")
	}
	if cfg.MaxIPs != 50 {
		t.Errorf("maxIPs = %d, want 50", cfg.MaxIPs)
	}
	if cfg.IPTTL != 24*time.Hour {
		t.Errorf("ipTTL = %v, want 24h", cfg.IPTTL)
	}
	if cfg.PrefixTTL != 24*time.Hour {
		t.Errorf("prefixTTL = %v, want 24h", cfg.PrefixTTL)
	}
}

func TestLoadAllowlistConfigOverrides(t *testing.T) {
	t.Setenv("ALLOWLIST_PATH", "/tmp/custom.json")
	t.Setenv("ALLOWLIST_MAX_IPS", "10")
	t.Setenv("ALLOWLIST_IP_TTL", "1h")
	t.Setenv("ALLOWLIST_PREFIX_TTL", "48h")

	cfg, err := loadAllowlist()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Path != "/tmp/custom.json" {
		t.Errorf("path = %q, want /tmp/custom.json", cfg.Path)
	}
	if cfg.MaxIPs != 10 {
		t.Errorf("maxIPs = %d, want 10", cfg.MaxIPs)
	}
	if cfg.IPTTL != time.Hour {
		t.Errorf("ipTTL = %v, want 1h", cfg.IPTTL)
	}
	if cfg.PrefixTTL != 48*time.Hour {
		t.Errorf("prefixTTL = %v, want 48h", cfg.PrefixTTL)
	}
}

func TestLoadServerConfigDefaults(t *testing.T) {
	cfg, err := loadServer()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.PublicAddr != ":8080" {
		t.Errorf("publicAddr = %q, want :8080", cfg.PublicAddr)
	}
	if cfg.PrivateAddr != ":9090" {
		t.Errorf("privateAddr = %q, want :9090", cfg.PrivateAddr)
	}
	if cfg.TLSEnabled() {
		t.Error("expected TLS disabled by default")
	}
}

func TestLoadServerConfigTLS(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "/etc/certs/tls.crt")
	t.Setenv("TLS_KEY_FILE", "/etc/certs/tls.key")

	cfg, err := loadServer()
	if err != nil {
		t.Fatal(err)
	}

	if !cfg.TLSEnabled() {
		t.Error("expected TLS enabled when both cert and key are set")
	}
	if cfg.TLSCertFile != "/etc/certs/tls.crt" {
		t.Errorf("tlsCertFile = %q, want /etc/certs/tls.crt", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/certs/tls.key" {
		t.Errorf("tlsKeyFile = %q, want /etc/certs/tls.key", cfg.TLSKeyFile)
	}
}

func TestLoadServerConfigTLSRequiresBoth(t *testing.T) {
	tests := map[string]struct {
		certFile string
		keyFile  string
	}{
		"cert without key": {certFile: "/etc/certs/tls.crt"},
		"key without cert": {keyFile: "/etc/certs/tls.key"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.certFile != "" {
				t.Setenv("TLS_CERT_FILE", tc.certFile)
			}
			if tc.keyFile != "" {
				t.Setenv("TLS_KEY_FILE", tc.keyFile)
			}
			if _, err := loadServer(); err == nil {
				t.Fatal("expected an error when only one of TLS_CERT_FILE/TLS_KEY_FILE is set")
			}
		})
	}
}

func TestLoadAllowlistConfigInvalidValues(t *testing.T) {
	tests := map[string]struct {
		envKey string
		value  string
	}{
		"bad max ips":    {"ALLOWLIST_MAX_IPS", "not-a-number"},
		"bad ip ttl":     {"ALLOWLIST_IP_TTL", "not-a-duration"},
		"bad prefix ttl": {"ALLOWLIST_PREFIX_TTL", "not-a-duration"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv(tc.envKey, tc.value)
			if _, err := loadAllowlist(); err == nil {
				t.Fatalf("expected an error for %s=%q", tc.envKey, tc.value)
			}
		})
	}
}

func TestLoadAuth(t *testing.T) {
	t.Setenv("IP_TOKENS", "token-a, token-b")
	t.Setenv("IP_TOKEN_1", "token-c")
	t.Setenv("DYNDNS_LOGINS", "alice:hunter2")
	t.Setenv("DYNDNS_LOGIN_1", "bob : correcthorse")

	cfg, err := loadAuth()
	if err != nil {
		t.Fatal(err)
	}

	tokens := map[string]bool{}
	for _, tok := range cfg.IPTokens {
		tokens[tok] = true
	}
	for _, want := range []string{"token-a", "token-b", "token-c"} {
		if !tokens[want] {
			t.Errorf("expected token %q in %v", want, cfg.IPTokens)
		}
	}
	if len(cfg.IPTokens) != 3 {
		t.Errorf("got %d tokens %v, want 3", len(cfg.IPTokens), cfg.IPTokens)
	}

	if got := cfg.Logins["alice"]; got != "hunter2" {
		t.Errorf("alice (comma list): password = %q, want hunter2", got)
	}
	if got := cfg.Logins["bob"]; got != "correcthorse" {
		t.Errorf("bob (indexed var, trimmed): password = %q, want correcthorse", got)
	}
}

func TestLoadAuthInvalidLoginEntry(t *testing.T) {
	t.Setenv("DYNDNS_LOGINS", "not-a-valid-pair")

	if _, err := loadAuth(); err == nil {
		t.Fatal("expected an error for a login entry missing ':'")
	}
}

func TestIndexedEnvValuesIgnoresUnrelatedVars(t *testing.T) {
	t.Setenv("IP_TOKENS", "should-not-match-indexed")
	t.Setenv("IP_TOKEN_1", "one")
	t.Setenv("IP_TOKEN_2", "two")
	t.Setenv("IP_TOKEN_EXTRA", "should-not-match")

	got := indexedEnvValues("IP_TOKEN_")

	want := map[string]bool{"one": true, "two": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want values matching %v", got, want)
	}
	for _, v := range got {
		if !want[v] {
			t.Errorf("unexpected value %q in %v", v, got)
		}
	}
}
