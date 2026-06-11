package directserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"

	"github.com/austinkregel/compute-agent/pkg/config"
	"github.com/austinkregel/compute-agent/pkg/logging"
)

const readLimit = 1 << 20 // 1 MiB per frame, matching the outbound transport

// Server is the inbound WSS listener for direct mode. Construction validates
// that the configuration is safe; Run serves until the context is cancelled.
type Server struct {
	cfg           *config.Config
	log           *logging.Logger
	verifier      *Verifier
	roots         []string
	maxBytes      int64
	probeInterval time.Duration
	sem           chan struct{} // bounds concurrent authenticated connections
}

// New validates the direct-mode config and builds the server. It returns an
// error (rather than starting insecurely) if TLS, OIDC, allowed roots, or the
// bind address are missing.
func New(cfg *config.Config, log *logging.Logger) (*Server, error) {
	dm := cfg.DirectMode
	if strings.TrimSpace(dm.ListenAddr) == "" {
		return nil, errors.New("directMode.listenAddr is required (bind to your VPN interface)")
	}
	if dm.TLSCertFile == "" || dm.TLSKeyFile == "" {
		return nil, errors.New("directMode requires tlsCertFile and tlsKeyFile (no plaintext listener)")
	}
	roots := dm.AllowedRoots
	if len(roots) == 0 {
		roots = cfg.DirBrowse.AllowedRoots
	}
	if len(roots) == 0 {
		return nil, errors.New("directMode requires allowedRoots (refusing to expose the whole filesystem)")
	}
	verifier, err := NewVerifier(dm.OIDC.Issuer, dm.OIDC.Audience, dm.OIDC.RequiredScope, dm.OIDC.MachineInfoProbe)
	if err != nil {
		return nil, err
	}

	maxConns := dm.MaxConns
	if maxConns <= 0 {
		maxConns = 4
	}
	maxBytes := dm.MaxUploadBytes
	if maxBytes <= 0 {
		maxBytes = 100 << 20
	}
	interval := time.Duration(dm.OIDC.ProbeIntervalSec) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}

	return &Server{
		cfg:           cfg,
		log:           log,
		verifier:      verifier,
		roots:         roots,
		maxBytes:      maxBytes,
		probeInterval: interval,
		sem:           make(chan struct{}, maxConns),
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	dm := s.cfg.DirectMode
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWS)

	// Hot-reload the TLS cert so wildcard renewals (e.g. *.kregel.host pulled by
	// download-ssl-certificates.sh) are picked up without restarting the agent.
	reloader := &certReloader{certFile: dm.TLSCertFile, keyFile: dm.TLSKeyFile}
	if _, err := reloader.GetCertificate(nil); err != nil {
		return err // refuse to serve without a loadable cert
	}

	server := &http.Server{
		Addr:              dm.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			GetCertificate: reloader.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		},
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	s.log.Info("direct mode listener starting",
		"addr", dm.ListenAddr, "issuer", dm.OIDC.Issuer, "roots", s.roots)
	// Cert/key come from TLSConfig.GetCertificate, so pass empty paths.
	err := server.ListenAndServeTLS("", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// certReloader serves the TLS cert via tls.Config.GetCertificate, reloading the
// PEM files whenever their modification time advances. A failed reload keeps the
// last good cert so a partial write during rotation can't take the listener down.
type certReloader struct {
	certFile, keyFile string

	mu        sync.Mutex
	cached    *tls.Certificate
	loadedMod time.Time
}

func (c *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	newest := time.Time{}
	for _, f := range []string{c.certFile, c.keyFile} {
		info, err := os.Stat(f)
		if err != nil {
			if c.cached != nil {
				return c.cached, nil
			}
			return nil, err
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}

	if c.cached == nil || newest.After(c.loadedMod) {
		cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
		if err != nil {
			if c.cached != nil {
				return c.cached, nil // serve the last good cert through a bad write
			}
			return nil, err
		}
		c.cached = &cert
		c.loadedMod = newest
	}
	return c.cached, nil
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	// 1. Require the Bearer token in the Authorization header. Browser
	//    WebSocket clients cannot set headers, so this structurally blocks
	//    drive-by web origins before any upgrade happens.
	token := bearerFromHeader(r.Header.Get("Authorization"))
	if token == "" {
		s.log.Warn("direct: rejected connection without bearer token", "remote", r.RemoteAddr)
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}

	// 2 & 3. Verify the token offline, then probe for revocation — both before
	//    spending a WebSocket on the connection.
	authCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	claims, err := s.verifier.Verify(authCtx, token)
	if err != nil {
		cancel()
		s.log.Warn("direct: token verification failed", "remote", r.RemoteAddr, "error", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := s.verifier.CheckRevocation(authCtx, token); err != nil {
		cancel()
		s.log.Warn("direct: revocation probe rejected token", "remote", r.RemoteAddr, "error", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	cancel()

	// 4. Enforce the connection cap.
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		s.log.Warn("direct: connection cap reached", "remote", r.RemoteAddr)
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}

	// 5. Upgrade and serve.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
	if err != nil {
		s.log.Debug("direct: websocket accept failed", "error", err)
		return
	}
	s.log.Info("direct: client authenticated", "remote", r.RemoteAddr, "jti", claims.Jti)
	s.serve(r.Context(), conn, token)
	s.log.Info("direct: client disconnected", "remote", r.RemoteAddr)
}

func (s *Server) serve(ctx context.Context, conn *websocket.Conn, token string) {
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer conn.Close(websocket.StatusNormalClosure, "")

	conn.SetReadLimit(readLimit)
	session := newSession(connCtx, conn, s.cfg, s.log, s.roots, s.maxBytes)
	defer session.close()

	// Honor revocation while connected: re-probe and drop the session if the
	// token stops being live.
	if s.verifier.probe {
		go s.reprobe(connCtx, cancel, token)
	}

	// Frames are dispatched sequentially per connection: one operation at a
	// time bounds resource use and avoids upload/stream interleaving races.
	for {
		typ, data, err := conn.Read(connCtx)
		if err != nil {
			return
		}
		if typ != websocket.MessageText {
			continue
		}
		var env struct {
			Event string          `json:"event"`
			Data  json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(data, &env); err != nil || env.Event == "" {
			continue
		}
		session.dispatch(env.Event, env.Data)
	}
}

func (s *Server) reprobe(ctx context.Context, cancel context.CancelFunc, token string) {
	ticker := time.NewTicker(s.probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			probeCtx, c := context.WithTimeout(ctx, 10*time.Second)
			err := s.verifier.CheckRevocation(probeCtx, token)
			c()
			if err != nil {
				s.log.Warn("direct: token no longer valid, closing connection", "error", err)
				cancel()
				return
			}
		}
	}
}

func bearerFromHeader(header string) string {
	const prefix = "Bearer "
	if len(header) > len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
		return strings.TrimSpace(header[len(prefix):])
	}
	return ""
}
