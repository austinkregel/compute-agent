package dirbrowse

import (
	"context"
	"errors"
	"net"
	"path"
	"strconv"
	"strings"
	"time"

	smb2 "github.com/hirochachacha/go-smb2"
)

type SMBRequest struct {
	Host    string
	Port    int
	Share   string
	Path    string
	Profile string
}

type SMBOptions struct {
	ConnectTimeout   time.Duration
	RequestTimeout   time.Duration
	MaxEntries       int
	MaxResponseBytes int
}

// SMBCredentials are provided from config (dirBrowse.smbProfiles[profile]).
type SMBCredentials struct {
	Username string
	Password string
	Domain   string
}

func ListSMB(ctx context.Context, req SMBRequest, cred SMBCredentials, opt SMBOptions) (Result, error) {
	if strings.TrimSpace(req.Host) == "" {
		return Result{}, errors.New("host is required for smb listing")
	}
	if strings.TrimSpace(req.Share) == "" {
		return Result{}, errors.New("share is required for smb listing")
	}
	remotePath, err := validateRemoteSlashPath(req.Path)
	if err != nil {
		return Result{}, err
	}

	port := req.Port
	if port == 0 {
		port = 445
	}
	if opt.ConnectTimeout <= 0 {
		opt.ConnectTimeout = 8 * time.Second
	}
	if opt.RequestTimeout <= 0 {
		opt.RequestTimeout = 12 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, opt.RequestTimeout)
	defer cancel()

	addr := net.JoinHostPort(req.Host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: opt.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     cred.Username,
			Password: cred.Password,
			Domain:   cred.Domain,
		},
	}

	sess, err := d.Dial(conn)
	if err != nil {
		return Result{}, err
	}
	defer sess.Logoff()

	share, err := sess.Mount(req.Share)
	if err != nil {
		return Result{}, err
	}
	defer share.Umount()

	// smb paths are relative to the share. RFC expects absolute paths; treat "/" as share root.
	rel := strings.TrimPrefix(remotePath, "/")
	rel = path.Clean("/" + rel)
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		rel = "."
	}

	infos, err := share.ReadDir(rel)
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
