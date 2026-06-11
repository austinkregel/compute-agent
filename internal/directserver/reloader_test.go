package directserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSelfSigned writes a fresh self-signed cert/key pair, returning the
// certificate serial so a reload can be detected.
func writeSelfSigned(t *testing.T, certPath, keyPath string, serial int64) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "test.kregel.host"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCertReloader_LoadsAndReloadsOnRotation(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	writeSelfSigned(t, certPath, keyPath, 1)

	r := &certReloader{certFile: certPath, keyFile: keyPath}

	first, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	if first.Leaf == nil {
		first.Leaf, _ = x509.ParseCertificate(first.Certificate[0])
	}
	if first.Leaf.SerialNumber.Int64() != 1 {
		t.Fatalf("serial = %d, want 1", first.Leaf.SerialNumber.Int64())
	}

	// Rotate the cert on disk with a later mtime; the reloader must pick it up.
	writeSelfSigned(t, certPath, keyPath, 2)
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(certPath, future, future)
	_ = os.Chtimes(keyPath, future, future)

	second, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	leaf, err := x509.ParseCertificate(second.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.SerialNumber.Int64() != 2 {
		t.Fatalf("after rotation serial = %d, want 2 (stale cert served)", leaf.SerialNumber.Int64())
	}
}

func TestCertReloader_MissingFile(t *testing.T) {
	r := &certReloader{certFile: "/nonexistent/cert.pem", keyFile: "/nonexistent/key.pem"}
	if _, err := r.GetCertificate(nil); err == nil {
		t.Fatal("expected error when cert files are missing")
	}
}
