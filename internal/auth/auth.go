// Package auth validates the credentials that gate the public endpoints:
// a shared pool of tokens for /unlock and one login per identity for /dyndns.
package auth

import "crypto/subtle"

type Authenticator struct {
	ipTokens []string
	logins   map[string]string // username -> password
}

func New(ipTokens []string, logins map[string]string) *Authenticator {
	return &Authenticator{ipTokens: ipTokens, logins: logins}
}

func (a *Authenticator) ValidateToken(token string) bool {
	for _, valid := range a.ipTokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(valid)) == 1 {
			return true
		}
	}
	return false
}

func (a *Authenticator) ValidateLogin(username, password string) bool {
	// Always run the comparison, even for an unknown username, rather than
	// short-circuiting on the map lookup - otherwise an unknown username
	// returns measurably faster than a known one with a wrong password,
	// letting a timing attack enumerate valid usernames.
	expected, ok := a.logins[username]
	match := subtle.ConstantTimeCompare([]byte(password), []byte(expected)) == 1
	return ok && match
}
