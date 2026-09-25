// Package tlscert serves a TLS certificate from disk and picks up renewals
// without a restart.
package tlscert

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// Reloader serves a TLS certificate loaded from disk, reloading it
// whenever the cert file's mtime advances. GetCertificate is checked on
// every TLS handshake, so a cert renewed in place (e.g. by certbot) takes
// effect on the next connection without restarting the process.
type Reloader struct {
	certFile, keyFile string

	mu       sync.Mutex
	cert     tls.Certificate
	loadedAt time.Time
}

// New loads the cert/key pair once up front, so a bad path fails at startup.
func New(certFile, keyFile string) (*Reloader, error) {
	r := &Reloader{certFile: certFile, keyFile: keyFile}
	if err := r.reloadLocked(); err != nil {
		return nil, err
	}
	return r, nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if info, err := os.Stat(r.certFile); err == nil && info.ModTime().After(r.loadedAt) {
		if err := r.reloadLocked(); err != nil {
			log.Printf("tls: failed to reload renewed cert, keeping previous one: %v", err)
		}
	}

	cert := r.cert
	return &cert, nil
}

// reloadLocked (re)loads the cert/key pair from disk. Caller must hold r.mu.
func (r *Reloader) reloadLocked() error {
	info, err := os.Stat(r.certFile)
	if err != nil {
		return fmt.Errorf("stat cert file: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("load cert/key pair: %w", err)
	}

	r.cert = cert
	r.loadedAt = info.ModTime()
	return nil
}
