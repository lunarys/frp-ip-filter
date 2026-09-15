package main

import (
	"testing"
	"time"
)

func TestLoadAllowlistConfigDefaults(t *testing.T) {
	cfg, err := loadAllowlistConfig()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.path != "allowlist.json" {
		t.Errorf("path = %q, want %q", cfg.path, "allowlist.json")
	}
	if cfg.maxIPs != 50 {
		t.Errorf("maxIPs = %d, want 50", cfg.maxIPs)
	}
	if cfg.ipTTL != 24*time.Hour {
		t.Errorf("ipTTL = %v, want 24h", cfg.ipTTL)
	}
	if cfg.prefixTTL != 24*time.Hour {
		t.Errorf("prefixTTL = %v, want 24h", cfg.prefixTTL)
	}
}

func TestLoadAllowlistConfigOverrides(t *testing.T) {
	t.Setenv("ALLOWLIST_PATH", "/tmp/custom.json")
	t.Setenv("ALLOWLIST_MAX_IPS", "10")
	t.Setenv("ALLOWLIST_IP_TTL", "1h")
	t.Setenv("ALLOWLIST_PREFIX_TTL", "48h")

	cfg, err := loadAllowlistConfig()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.path != "/tmp/custom.json" {
		t.Errorf("path = %q, want /tmp/custom.json", cfg.path)
	}
	if cfg.maxIPs != 10 {
		t.Errorf("maxIPs = %d, want 10", cfg.maxIPs)
	}
	if cfg.ipTTL != time.Hour {
		t.Errorf("ipTTL = %v, want 1h", cfg.ipTTL)
	}
	if cfg.prefixTTL != 48*time.Hour {
		t.Errorf("prefixTTL = %v, want 48h", cfg.prefixTTL)
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
			if _, err := loadAllowlistConfig(); err == nil {
				t.Fatalf("expected an error for %s=%q", tc.envKey, tc.value)
			}
		})
	}
}
