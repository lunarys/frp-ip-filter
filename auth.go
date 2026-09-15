package main

import (
	"crypto/subtle"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// authConfig holds the credentials that gate /register (a shared pool of
// tokens) and /dyndns (one login per identity). Loaded once at startup from
// env vars, since this is meant to run as a container with static config.
type authConfig struct {
	ipTokens []string
	logins   map[string]string // username -> password
}

func loadAuthConfigFromEnv() (*authConfig, error) {
	logins, err := loadLogins()
	if err != nil {
		return nil, err
	}

	return &authConfig{
		ipTokens: loadIPTokens(),
		logins:   logins,
	}, nil
}

func (c *authConfig) validateToken(token string) bool {
	for _, valid := range c.ipTokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(valid)) == 1 {
			return true
		}
	}
	return false
}

func (c *authConfig) validateLogin(username, password string) bool {
	expected, ok := c.logins[username]
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(password), []byte(expected)) == 1
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
