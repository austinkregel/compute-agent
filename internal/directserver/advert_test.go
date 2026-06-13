package directserver

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/austinkregel/compute-agent/pkg/config"
)

func advertConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeSelfSigned(t, certPath, keyPath, 42)

	cfg := baseDirectConfig()
	cfg.DirectMode.TLSCertFile = certPath
	cfg.DirectMode.TLSKeyFile = keyPath
	return cfg
}

func leafFingerprint(t *testing.T, cfg *config.Config) string {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(cfg.DirectMode.TLSCertFile, cfg.DirectMode.TLSKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:])
}

func TestAdvert_SelfSignedRequiresPin(t *testing.T) {
	cfg := advertConfig(t)
	s, err := New(cfg, mustLog(t))
	if err != nil {
		t.Fatal(err)
	}

	adv, err := s.Advert()
	if err != nil {
		t.Fatalf("Advert: %v", err)
	}
	if adv.Addr != cfg.DirectMode.ListenAddr {
		t.Errorf("addr = %q, want ListenAddr %q", adv.Addr, cfg.DirectMode.ListenAddr)
	}
	if !adv.PinRequired {
		t.Error("self-signed cert should require a pin")
	}
	if adv.Scheme != "wss" {
		t.Errorf("scheme = %q, want wss", adv.Scheme)
	}
	if want := leafFingerprint(t, cfg); adv.CertSha256 != want {
		t.Errorf("certSha256 = %q, want %q", adv.CertSha256, want)
	}
}

func TestAdvert_UsesAdvertiseAddrWhenSet(t *testing.T) {
	cfg := advertConfig(t)
	cfg.DirectMode.AdvertiseAddr = "100.64.0.5:7420"
	s, err := New(cfg, mustLog(t))
	if err != nil {
		t.Fatal(err)
	}
	adv, err := s.Advert()
	if err != nil {
		t.Fatal(err)
	}
	if adv.Addr != "100.64.0.5:7420" {
		t.Errorf("addr = %q, want advertise addr", adv.Addr)
	}
}

func TestAdvert_PublicCertSelfSignedStillPins(t *testing.T) {
	// PublicCert=true but the cert is self-signed (Issuer==Subject) → still pin.
	cfg := advertConfig(t)
	cfg.DirectMode.PublicCert = true
	s, err := New(cfg, mustLog(t))
	if err != nil {
		t.Fatal(err)
	}
	adv, err := s.Advert()
	if err != nil {
		t.Fatal(err)
	}
	if !adv.PinRequired {
		t.Error("a self-signed cert must require a pin even with PublicCert=true")
	}
}
