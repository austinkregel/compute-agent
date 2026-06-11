package directserver

import (
	"testing"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
)

func mustLog(t *testing.T) *logging.Logger {
	t.Helper()
	l, err := logging.New(logging.Options{Level: "error"})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func baseDirectConfig() *config.Config {
	return &config.Config{
		ClientID: "agent-1",
		DirectMode: config.DirectModeConfig{
			Enabled:      true,
			ListenAddr:   "127.0.0.1:7420",
			TLSCertFile:  "/tmp/cert.pem",
			TLSKeyFile:   "/tmp/key.pem",
			AllowedRoots: []string{"/home/dev/project"},
			OIDC: config.DirectOIDCConfig{
				Issuer:        "https://aut.hair",
				Audience:      "rebase-ide",
				RequiredScope: "openid",
			},
		},
	}
}

// New must refuse to start when a safety prerequisite is missing, rather than
// listening insecurely.
func TestServerNew_RefusesUnsafeConfig(t *testing.T) {
	log := mustLog(t)

	cases := map[string]func(*config.Config){
		"no listen addr": func(c *config.Config) { c.DirectMode.ListenAddr = "" },
		"no tls cert":    func(c *config.Config) { c.DirectMode.TLSCertFile = "" },
		"no tls key":     func(c *config.Config) { c.DirectMode.TLSKeyFile = "" },
		"no allowed roots": func(c *config.Config) {
			c.DirectMode.AllowedRoots = nil
			c.DirBrowse.AllowedRoots = nil
		},
		"plaintext issuer": func(c *config.Config) { c.DirectMode.OIDC.Issuer = "http://aut.hair" },
		"no audience":      func(c *config.Config) { c.DirectMode.OIDC.Audience = "" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := baseDirectConfig()
			mutate(cfg)
			if _, err := New(cfg, log); err == nil {
				t.Fatalf("expected New to reject config (%s)", name)
			}
		})
	}
}

func TestServerNew_AcceptsSafeConfig(t *testing.T) {
	if _, err := New(baseDirectConfig(), mustLog(t)); err != nil {
		t.Fatalf("expected valid config to be accepted, got %v", err)
	}
}

func TestServerNew_FallsBackToDirBrowseRoots(t *testing.T) {
	cfg := baseDirectConfig()
	cfg.DirectMode.AllowedRoots = nil
	cfg.DirBrowse.AllowedRoots = []string{"/srv/work"}
	s, err := New(cfg, mustLog(t))
	if err != nil {
		t.Fatalf("expected fallback to DirBrowse roots, got %v", err)
	}
	if len(s.roots) != 1 || s.roots[0] != "/srv/work" {
		t.Fatalf("roots = %v", s.roots)
	}
}

func TestBearerFromHeader(t *testing.T) {
	cases := map[string]string{
		"Bearer abc.def.ghi": "abc.def.ghi",
		"bearer abc":         "abc",
		"Basic abc":          "",
		"":                   "",
		"Bearer ":            "",
	}
	for header, want := range cases {
		if got := bearerFromHeader(header); got != want {
			t.Fatalf("bearerFromHeader(%q) = %q, want %q", header, got, want)
		}
	}
}
