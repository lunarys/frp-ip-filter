package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type allowlistConfig struct {
	path      string
	maxIPs    int
	ipTTL     time.Duration
	prefixTTL time.Duration
}

func loadAllowlistConfig() (*allowlistConfig, error) {
	cfg := &allowlistConfig{
		path:      "allowlist.json",
		maxIPs:    50,
		ipTTL:     24 * time.Hour,
		prefixTTL: 24 * time.Hour,
	}

	if v, ok := os.LookupEnv("ALLOWLIST_PATH"); ok {
		cfg.path = v
	}

	if v, ok := os.LookupEnv("ALLOWLIST_MAX_IPS"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid ALLOWLIST_MAX_IPS %q: %w", v, err)
		}
		cfg.maxIPs = n
	}

	if v, ok := os.LookupEnv("ALLOWLIST_IP_TTL"); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("invalid ALLOWLIST_IP_TTL %q: %w", v, err)
		}
		cfg.ipTTL = d
	}

	if v, ok := os.LookupEnv("ALLOWLIST_PREFIX_TTL"); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("invalid ALLOWLIST_PREFIX_TTL %q: %w", v, err)
		}
		cfg.prefixTTL = d
	}

	return cfg, nil
}

type serverConfig struct {
	publicAddr  string
	privateAddr string
	tlsCertFile string
	tlsKeyFile  string
}

func (c *serverConfig) tlsEnabled() bool {
	return c.tlsCertFile != ""
}

func loadServerConfig() (*serverConfig, error) {
	cfg := &serverConfig{
		publicAddr:  ":8080",
		privateAddr: ":9090",
	}

	if v, ok := os.LookupEnv("PUBLIC_ADDR"); ok {
		cfg.publicAddr = v
	}
	if v, ok := os.LookupEnv("PRIVATE_ADDR"); ok {
		cfg.privateAddr = v
	}

	cfg.tlsCertFile = os.Getenv("TLS_CERT_FILE")
	cfg.tlsKeyFile = os.Getenv("TLS_KEY_FILE")
	if (cfg.tlsCertFile == "") != (cfg.tlsKeyFile == "") {
		return nil, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must both be set, or neither")
	}

	return cfg, nil
}

type loggingConfig struct {
	accessLog bool
	frpDebug  bool
}

func loadLoggingConfig() (*loggingConfig, error) {
	cfg := &loggingConfig{
		accessLog: true,
		frpDebug:  false,
	}

	if v, ok := os.LookupEnv("ACCESS_LOG"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid ACCESS_LOG %q: %w", v, err)
		}
		cfg.accessLog = b
	}

	if v, ok := os.LookupEnv("FRP_DEBUG"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid FRP_DEBUG %q: %w", v, err)
		}
		cfg.frpDebug = b
	}

	return cfg, nil
}
