// Package config loads all runtime configuration from environment variables.
// It is the only package that reads the environment; everything else gets
// plain values passed in.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Allowlist Allowlist
	Server    Server
	Logging   Logging
	Auth      Auth
}

type Allowlist struct {
	Path      string
	MaxIPs    int
	IPTTL     time.Duration
	PrefixTTL time.Duration
}

type Server struct {
	PublicAddr  string
	PrivateAddr string
	TLSCertFile string
	TLSKeyFile  string
}

func (s Server) TLSEnabled() bool {
	return s.TLSCertFile != ""
}

type Logging struct {
	AccessLog bool
	FrpDebug  bool
}

// Auth holds the credentials that gate /unlock (a shared pool of tokens) and
// /dyndns (one login per identity).
type Auth struct {
	IPTokens []string
	Logins   map[string]string // username -> password
}

func Load() (*Config, error) {
	var cfg Config
	var err error
	if cfg.Allowlist, err = loadAllowlist(); err != nil {
		return nil, err
	}
	if cfg.Server, err = loadServer(); err != nil {
		return nil, err
	}
	if cfg.Logging, err = loadLogging(); err != nil {
		return nil, err
	}
	if cfg.Auth, err = loadAuth(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func loadAllowlist() (Allowlist, error) {
	cfg := Allowlist{
		Path:      "allowlist.json",
		MaxIPs:    50,
		IPTTL:     24 * time.Hour,
		PrefixTTL: 24 * time.Hour,
	}

	if v, ok := os.LookupEnv("ALLOWLIST_PATH"); ok {
		cfg.Path = v
	}

	if v, ok := os.LookupEnv("ALLOWLIST_MAX_IPS"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Allowlist{}, fmt.Errorf("invalid ALLOWLIST_MAX_IPS %q: %w", v, err)
		}
		cfg.MaxIPs = n
	}

	if v, ok := os.LookupEnv("ALLOWLIST_IP_TTL"); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Allowlist{}, fmt.Errorf("invalid ALLOWLIST_IP_TTL %q: %w", v, err)
		}
		cfg.IPTTL = d
	}

	if v, ok := os.LookupEnv("ALLOWLIST_PREFIX_TTL"); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Allowlist{}, fmt.Errorf("invalid ALLOWLIST_PREFIX_TTL %q: %w", v, err)
		}
		cfg.PrefixTTL = d
	}

	return cfg, nil
}

func loadServer() (Server, error) {
	cfg := Server{
		PublicAddr:  ":8080",
		PrivateAddr: ":9090",
	}

	if v, ok := os.LookupEnv("PUBLIC_ADDR"); ok {
		cfg.PublicAddr = v
	}
	if v, ok := os.LookupEnv("PRIVATE_ADDR"); ok {
		cfg.PrivateAddr = v
	}

	cfg.TLSCertFile = os.Getenv("TLS_CERT_FILE")
	cfg.TLSKeyFile = os.Getenv("TLS_KEY_FILE")
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return Server{}, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must both be set, or neither")
	}

	return cfg, nil
}

func loadLogging() (Logging, error) {
	cfg := Logging{
		AccessLog: true,
		FrpDebug:  false,
	}

	if v, ok := os.LookupEnv("ACCESS_LOG"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Logging{}, fmt.Errorf("invalid ACCESS_LOG %q: %w", v, err)
		}
		cfg.AccessLog = b
	}

	if v, ok := os.LookupEnv("FRP_DEBUG"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Logging{}, fmt.Errorf("invalid FRP_DEBUG %q: %w", v, err)
		}
		cfg.FrpDebug = b
	}

	return cfg, nil
}

func loadAuth() (Auth, error) {
	logins, err := loadLogins()
	if err != nil {
		return Auth{}, err
	}
	return Auth{IPTokens: loadIPTokens(), Logins: logins}, nil
}

func loadIPTokens() []string {
	tokens := splitCommaList(os.Getenv("IP_TOKENS"))
	tokens = append(tokens, indexedEnvValues("IP_TOKEN_")...)
	return tokens
}

func loadLogins() (map[string]string, error) {
	logins := make(map[string]string)

	add := func(entries []string) error {
		for _, entry := range entries {
			username, password, ok := strings.Cut(entry, ":")
			if !ok {
				return fmt.Errorf("invalid login entry %q: expected user:pass", entry)
			}
			logins[strings.TrimSpace(username)] = strings.TrimSpace(password)
		}
		return nil
	}

	if err := add(splitCommaList(os.Getenv("DYNDNS_LOGINS"))); err != nil {
		return nil, err
	}
	if err := add(indexedEnvValues("DYNDNS_LOGIN_")); err != nil {
		return nil, err
	}

	return logins, nil
}

func splitCommaList(s string) []string {
	if s == "" {
		return nil
	}

	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// indexedEnvValues returns the values of every env var matching
// "<prefix><digits>", e.g. IP_TOKEN_1, IP_TOKEN_2. Order and gaps in the
// numbering don't matter - every match is collected.
func indexedEnvValues(prefix string) []string {
	pattern := regexp.MustCompile(`^` + regexp.QuoteMeta(prefix) + `\d+$`)

	var out []string
	for _, kv := range os.Environ() {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || !pattern.MatchString(key) {
			continue
		}
		out = append(out, strings.TrimSpace(value))
	}
	return out
}
