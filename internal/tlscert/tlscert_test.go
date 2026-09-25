package tlscert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateSelfSignedCert produces a fresh self-signed cert/key pair each
// call (distinct serial + key), so two calls are guaranteed to differ - used
// to tell which one Reloader is currently serving.
func generateSelfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

func writeCert(t *testing.T, certPath, keyPath string, certPEM, keyPEM []byte) {
	t.Helper()
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReloadingCertReloadsAfterFileChanges(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")

	certA, keyA := generateSelfSignedCert(t)
	writeCert(t, certPath, keyPath, certA, keyA)

	r, err := New(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}

	got, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Certificate[0], r.cert.Certificate[0]) {
		t.Fatal("sanity check: GetCertificate should return the loaded cert")
	}
	initialDER := got.Certificate[0]

	certB, keyB := generateSelfSignedCert(t)
	writeCert(t, certPath, keyPath, certB, keyB)
	// Force the mtime forward: some filesystems have 1s mtime resolution,
	// which could otherwise make this write look no newer than the first.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatal(err)
	}

	got, err = r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got.Certificate[0], initialDER) {
		t.Fatal("expected GetCertificate to serve the renewed cert after the file changed")
	}
}

func TestReloadingCertKeepsServingOldCertIfReloadFails(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")

	certA, keyA := generateSelfSignedCert(t)
	writeCert(t, certPath, keyPath, certA, keyA)

	r, err := New(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	initialDER := r.cert.Certificate[0]

	// Simulate a renewal tool mid-write: cert file updated (and newly
	// mtime'd) but the key file left stale/mismatched.
	certB, _ := generateSelfSignedCert(t)
	if err := os.WriteFile(certPath, certB, 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatal(err)
	}

	got, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Certificate[0], initialDER) {
		t.Fatal("expected the previous cert to keep being served when a reload fails")
	}
}
