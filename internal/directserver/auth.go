// Package directserver implements the agent's optional inbound listener that
// lets a trusted IDE client connect directly over a private network, bypassing
// the control plane. It is the agent's only network-facing inbound surface, so
// authentication and authorization are deliberately strict — see auth.go for
// the token trust boundary and session.go for the least-privilege command set.
package directserver

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// clockSkew tolerates modest agent/issuer clock drift on exp/nbf checks.
const clockSkew = 60 * time.Second

// Claims is the subset of the Machine Token (aut.hair client_credentials JWT)
// we validate. aut.hair emits scopes as an array; we also accept the standard
// space-delimited `scope` string.
type Claims struct {
	Iss    string   `json:"iss"`
	Aud    audience `json:"aud"`
	Exp    int64    `json:"exp"`
	Nbf    int64    `json:"nbf"`
	Scope  string   `json:"scope"`
	Scopes []string `json:"scopes"`
	Jti    string   `json:"jti"`
}

func (c *Claims) hasScope(want string) bool {
	if want == "" {
		return true
	}
	for _, s := range c.Scopes {
		if s == want {
			return true
		}
	}
	for _, s := range strings.Fields(c.Scope) {
		if s == want {
			return true
		}
	}
	return false
}

// audience decodes a JWT `aud` claim, which may be a string or an array.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

func (a audience) contains(want string) bool {
	for _, v := range a {
		if v == want {
			return true
		}
	}
	return false
}

type discovery struct {
	JwksURI             string `json:"jwks_uri"`
	MachineInfoEndpoint string `json:"machine_info_endpoint"`
}

// Verifier validates Machine Tokens offline against the issuer's JWKS and
// (optionally) probes /api/machine-info to honor revocation. Safe for
// concurrent use.
type Verifier struct {
	issuer        string
	audience      string
	requiredScope string
	probe         bool
	http          *http.Client

	mu       sync.Mutex
	disco    *discovery
	keys     map[string]*rsa.PublicKey // kid -> key
	keysAtMS int64
}

// NewVerifier requires an https issuer and a non-empty audience. It performs no
// network I/O until the first verification.
func NewVerifier(issuer, audience, requiredScope string, probe bool) (*Verifier, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if !strings.HasPrefix(issuer, "https://") {
		return nil, errors.New("oidc issuer must be an https URL")
	}
	if strings.TrimSpace(audience) == "" {
		return nil, errors.New("oidc audience (rebase-ide client_id) is required")
	}
	if requiredScope == "" {
		requiredScope = "openid"
	}
	return &Verifier{
		issuer:        issuer,
		audience:      audience,
		requiredScope: requiredScope,
		probe:         probe,
		http:          &http.Client{Timeout: 10 * time.Second},
		keys:          map[string]*rsa.PublicKey{},
	}, nil
}

// Verify checks a raw compact JWT: RS256 signature against the issuer JWKS,
// then iss / aud / exp / nbf / scope. Returns the validated claims.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed JWT")
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	headerJSON, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}
	// Pin RS256 — never trust the token's choice of "none" or an HMAC alg, which
	// would enable algorithm-confusion attacks against a public verifier.
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported JWT alg %q (only RS256)", header.Alg)
	}

	key, err := v.keyForKid(ctx, header.Kid)
	if err != nil {
		return nil, err
	}

	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return nil, errors.New("invalid token signature")
	}

	payloadJSON, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	now := time.Now()
	if claims.Iss != v.issuer {
		return nil, fmt.Errorf("issuer mismatch: %q", claims.Iss)
	}
	if !claims.Aud.contains(v.audience) {
		return nil, errors.New("token audience is not this IDE client")
	}
	if claims.Exp == 0 || now.After(time.Unix(claims.Exp, 0).Add(clockSkew)) {
		return nil, errors.New("token expired")
	}
	if claims.Nbf != 0 && now.Before(time.Unix(claims.Nbf, 0).Add(-clockSkew)) {
		return nil, errors.New("token not yet valid")
	}
	if !claims.hasScope(v.requiredScope) {
		return nil, fmt.Errorf("token missing required scope %q", v.requiredScope)
	}
	return &claims, nil
}

// CheckRevocation probes /api/machine-info with the caller's token. A 401/403
// means the token was revoked or downgraded; any non-2xx is treated as not
// live. No-op when probing is disabled.
func (v *Verifier) CheckRevocation(ctx context.Context, raw string) error {
	if !v.probe {
		return nil
	}
	disco, err := v.discovery(ctx)
	if err != nil {
		return err
	}
	if disco.MachineInfoEndpoint == "" {
		return errors.New("issuer advertises no machine_info_endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, disco.MachineInfoEndpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("machine-info probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("machine-info probe rejected token (status %d)", resp.StatusCode)
	}
	return nil
}

func (v *Verifier) keyForKid(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	key, ok := v.keys[kid]
	v.mu.Unlock()
	if ok {
		return key, nil
	}
	// Unknown kid — (re)fetch JWKS once, then look again. Rate-limited to avoid
	// a fetch storm on bogus kids.
	if err := v.refreshKeys(ctx); err != nil {
		return nil, err
	}
	v.mu.Lock()
	key, ok = v.keys[kid]
	v.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no JWKS key for kid %q", kid)
	}
	return key, nil
}

func (v *Verifier) refreshKeys(ctx context.Context) error {
	v.mu.Lock()
	recent := v.keysAtMS != 0 && time.Now().UnixMilli()-v.keysAtMS < 30_000
	v.mu.Unlock()
	if recent {
		return nil // fetched within 30s; treat as definitively unknown kid
	}

	disco, err := v.discovery(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, disco.JwksURI, nil)
	if err != nil {
		return err
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint status %d", resp.StatusCode)
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("parse jwks: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := rsaKey(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return errors.New("jwks contained no usable RSA keys")
	}
	v.mu.Lock()
	v.keys = keys
	v.keysAtMS = time.Now().UnixMilli()
	v.mu.Unlock()
	return nil
}

func (v *Verifier) discovery(ctx context.Context) (*discovery, error) {
	v.mu.Lock()
	if v.disco != nil {
		d := v.disco
		v.mu.Unlock()
		return d, nil
	}
	v.mu.Unlock()

	url := v.issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery status %d", resp.StatusCode)
	}
	var d discovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("parse discovery: %w", err)
	}
	if d.JwksURI == "" {
		return nil, errors.New("discovery missing jwks_uri")
	}
	v.mu.Lock()
	v.disco = &d
	v.mu.Unlock()
	return &d, nil
}

var b64 = base64.RawURLEncoding

func rsaKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := b64.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := b64.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() <= 0 {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}
