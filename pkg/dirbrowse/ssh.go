package dirbrowse

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

type SSHRequest struct {
	Host string
	User string
	Port int
	Path string
}

type SSHOptions struct {
	HostKeyPolicy    string
	ConnectTimeout   time.Duration
	RequestTimeout   time.Duration
	MaxEntries       int
	MaxResponseBytes int
}

func ListSSH(ctx context.Context, req SSHRequest, opt SSHOptions) (Result, error) {
	if strings.TrimSpace(req.Host) == "" {
		return Result{}, errors.New("host is required for ssh listing")
	}
	remotePath, err := validateRemoteSlashPath(req.Path)
	if err != nil {
		return Result{}, err
	}
	port := req.Port
	if port == 0 {
		port = 22
	}
	userName := strings.TrimSpace(req.User)
	if userName == "" {
		userName = defaultSSHUser()
	}
	if opt.ConnectTimeout <= 0 {
		opt.ConnectTimeout = 8 * time.Second
	}
	if opt.RequestTimeout <= 0 {
		opt.RequestTimeout = 12 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, opt.RequestTimeout)
	defer cancel()

	authMethods := sshAuthMethods()
	if len(authMethods) == 0 {
		return Result{}, errors.New("no SSH auth methods available (no SSH agent and no readable private keys)")
	}

	hostKeyCb, err := hostKeyCallback(opt.HostKeyPolicy)
	if err != nil {
		return Result{}, err
	}

	cfg := &ssh.ClientConfig{
		User:            userName,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCb,
		Timeout:         opt.ConnectTimeout,
	}

	addr := net.JoinHostPort(req.Host, strconv.Itoa(port))

	// ssh.Dial does not accept context; use a net.Dialer with timeout and then handshake.
	dialer := &net.Dialer{Timeout: opt.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opt.RequestTimeout))

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		return Result{}, err
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return Result{}, err
	}
	defer sftpClient.Close()

	infos, err := sftpClient.ReadDir(remotePath)
	if err != nil {
		return Result{}, err
	}

	maxEntries := opt.MaxEntries
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	maxBytes := opt.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxResponseSize
	}

	var out []Entry
	approxBytes := 0
	truncated := false
	var truncReason string

	for _, fi := range infos {
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		default:
		}
		name := fi.Name()
		if name == "" || name == "." || name == ".." {
			continue
		}
		typ := "file"
		size := int64(0)
		if fi.IsDir() {
			typ = "dir"
		} else {
			size = fi.Size()
		}
		approxBytes += len(name) + 16
		if len(out) >= maxEntries || approxBytes > maxBytes {
			truncated = true
			truncReason = "listing truncated due to size limits"
			break
		}
		out = append(out, Entry{Name: name, Type: typ, Size: size})
	}

	sortEntries(out)
	return Result{
		Path:          remotePath,
		Entries:       out,
		Truncated:     truncated,
		TruncateError: truncReason,
	}, nil
}

func validateRemoteSlashPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", errors.New("path is required")
	}
	if strings.ContainsRune(p, '\x00') {
		return "", errors.New("path contains NUL byte")
	}
	if strings.Contains(p, "\\") {
		// Normalize Windows-style separators for remote paths.
		p = strings.ReplaceAll(p, "\\", "/")
	}
	if containsDotDotSegment(p) {
		return "", errors.New("path contains traversal segment '..'")
	}
	clean := path.Clean(p)
	if !strings.HasPrefix(clean, "/") {
		return "", errors.New("path must be absolute")
	}
	return clean, nil
}

func defaultSSHUser() string {
	if u, err := user.Current(); err == nil && u != nil && u.Username != "" {
		// On some systems Username may include domain; that's still acceptable for SSH.
		return u.Username
	}
	if v := strings.TrimSpace(os.Getenv("USER")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("USERNAME")); v != "" {
		return v
	}
	return "root"
}

func sshAuthMethods() []ssh.AuthMethod {
	var out []ssh.AuthMethod

	// Prefer SSH agent if available.
	if sock := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK")); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			ag := agent.NewClient(conn)
			out = append(out, ssh.PublicKeysCallback(ag.Signers))
			// Keep the agent connection alive for the duration of the request.
			// It will be closed when the process exits; for a longer-lived lister, we can manage lifecycle explicitly.
		}
	}

	// Fallback: try default private key locations (unencrypted keys only).
	if u, err := user.Current(); err == nil && u != nil && u.HomeDir != "" {
		sshDir := filepath.Join(u.HomeDir, ".ssh")
		candidates := []string{
			filepath.Join(sshDir, "id_ed25519"),
			filepath.Join(sshDir, "id_rsa"),
			filepath.Join(sshDir, "id_ecdsa"),
		}
		for _, p := range candidates {
			raw, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			signer, err := ssh.ParsePrivateKey(raw)
			if err != nil {
				// Encrypted keys require a passphrase prompt; skip.
				continue
			}
			out = append(out, ssh.PublicKeys(signer))
		}
	}

	return out
}

func hostKeyCallback(policy string) (ssh.HostKeyCallback, error) {
	switch strings.TrimSpace(policy) {
	case "", "known_hosts":
		kh := defaultKnownHostsPath()
		if kh == "" {
			return nil, errors.New("cannot resolve known_hosts path")
		}
		cb, err := knownhosts.New(kh)
		if err != nil {
			return nil, fmt.Errorf("known_hosts: %w", err)
		}
		return cb, nil
	case "insecure_accept_any":
		return ssh.InsecureIgnoreHostKey(), nil
	default:
		return nil, fmt.Errorf("unsupported sshHostKeyPolicy %q", policy)
	}
}

func defaultKnownHostsPath() string {
	if u, err := user.Current(); err == nil && u != nil && u.HomeDir != "" {
		return filepath.Join(u.HomeDir, ".ssh", "known_hosts")
	}
	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" {
		return filepath.Join(home, ".ssh", "known_hosts")
	}
	return ""
}
