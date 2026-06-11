package directserver

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// testIDP spins up a fake issuer serving discovery + JWKS, and signs tokens
// with a known RSA key so we can exercise the verifier's checks directly.
type testIDP struct {
	server  *httptest.Server
	key     *rsa.PrivateKey
	kid     string
	machine func(token string) int // status code for /api/machine-info
}

func newTestIDP(t *testing.T) *testIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &testIDP{key: key, kid: "test-key-1", machine: func(string) int { return http.StatusOK }}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                idp.server.URL,
			"jwks_uri":              idp.server.URL + "/oauth/jwks",
			"machine_info_endpoint": idp.server.URL + "/api/machine-info",
		})
	})
	mux.HandleFunc("/oauth/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{"kty": "RSA", "kid": idp.kid, "n": n, "e": e},
			},
		})
	})
	mux.HandleFunc("/api/machine-info", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(idp.machine(r.Header.Get("Authorization")))
	})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (idp *testIDP) sign(t *testing.T, alg string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": alg, "kid": idp.kid, "typ": "JWT"}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	if alg == "none" {
		return signingInput + "."
	}
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func validClaims(idp *testIDP) map[string]any {
	return map[string]any{
		"iss":    idp.server.URL,
		"aud":    "rebase-ide",
		"exp":    time.Now().Add(time.Hour).Unix(),
		"scopes": []string{"openid"},
		"jti":    "tok-1",
	}
}

func newTestVerifier(_ *testing.T, idp *testIDP) *Verifier {
	// httptest serves http://; the production NewVerifier guard requires https
	// (covered by TestNewVerifier_RequiresHTTPSAndAudience), so build the struct
	// directly here to exercise the token checks against the fake issuer.
	return &Verifier{
		issuer:        idp.server.URL,
		audience:      "rebase-ide",
		requiredScope: "openid",
		probe:         true,
		http:          &http.Client{Timeout: 10 * time.Second},
		keys:          map[string]*rsa.PublicKey{},
	}
}

func TestVerify_ValidToken(t *testing.T) {
	idp := newTestIDP(t)
	v := newTestVerifier(t, idp)
	claims, err := v.Verify(context.Background(), idp.sign(t, "RS256", validClaims(idp)))
	if err != nil {
		t.Fatalf("expected valid token, got %v", err)
	}
	if claims.Jti != "tok-1" {
		t.Fatalf("jti = %q", claims.Jti)
	}
}

func TestVerify_RejectsAlgNone(t *testing.T) {
	idp := newTestIDP(t)
	v := newTestVerifier(t, idp)
	if _, err := v.Verify(context.Background(), idp.sign(t, "none", validClaims(idp))); err == nil {
		t.Fatal("alg=none must be rejected")
	}
}

func TestVerify_RejectsWrongAudience(t *testing.T) {
	idp := newTestIDP(t)
	v := newTestVerifier(t, idp)
	c := validClaims(idp)
	c["aud"] = "some-other-client"
	if _, err := v.Verify(context.Background(), idp.sign(t, "RS256", c)); err == nil {
		t.Fatal("wrong audience must be rejected")
	}
}

func TestVerify_RejectsExpired(t *testing.T) {
	idp := newTestIDP(t)
	v := newTestVerifier(t, idp)
	c := validClaims(idp)
	c["exp"] = time.Now().Add(-2 * time.Hour).Unix()
	if _, err := v.Verify(context.Background(), idp.sign(t, "RS256", c)); err == nil {
		t.Fatal("expired token must be rejected")
	}
}

func TestVerify_RejectsMissingScope(t *testing.T) {
	idp := newTestIDP(t)
	v := newTestVerifier(t, idp)
	c := validClaims(idp)
	c["scopes"] = []string{"profile"}
	if _, err := v.Verify(context.Background(), idp.sign(t, "RS256", c)); err == nil {
		t.Fatal("token without required scope must be rejected")
	}
}

func TestVerify_RejectsTamperedSignature(t *testing.T) {
	idp := newTestIDP(t)
	v := newTestVerifier(t, idp)
	token := idp.sign(t, "RS256", validClaims(idp)) + "tampered"
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("tampered signature must be rejected")
	}
}

func TestVerify_RejectsWrongIssuer(t *testing.T) {
	idp := newTestIDP(t)
	v := newTestVerifier(t, idp)
	c := validClaims(idp)
	c["iss"] = "https://evil.example"
	if _, err := v.Verify(context.Background(), idp.sign(t, "RS256", c)); err == nil {
		t.Fatal("wrong issuer must be rejected")
	}
}

func TestCheckRevocation_RejectsOn401(t *testing.T) {
	idp := newTestIDP(t)
	idp.machine = func(string) int { return http.StatusUnauthorized }
	v := newTestVerifier(t, idp)
	if err := v.CheckRevocation(context.Background(), "any"); err == nil {
		t.Fatal("revoked token (401 from machine-info) must be rejected")
	}
}

func TestNewVerifier_RequiresHTTPSAndAudience(t *testing.T) {
	if _, err := NewVerifier("http://aut.hair", "rebase-ide", "openid", true); err == nil {
		t.Fatal("non-https issuer must be rejected")
	}
	if _, err := NewVerifier("https://aut.hair", "", "openid", true); err == nil {
		t.Fatal("empty audience must be rejected")
	}
}
