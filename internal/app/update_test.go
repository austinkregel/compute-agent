package app

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSha256FileHex(t *testing.T) {
	p := filepath.Join(t.TempDir(), "file.bin")
	data := []byte("hello world")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])

	got, err := sha256FileHex(p)
	if err != nil {
		t.Fatalf("sha256FileHex: %v", err)
	}
	if got != want {
		t.Fatalf("sha256FileHex = %q, want %q", got, want)
	}
}

func TestExpectedBinaryName(t *testing.T) {
	want := "backup-agent-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		want += ".exe"
	}
	if got := expectedBinaryName(); got != want {
		t.Fatalf("expectedBinaryName() = %q, want %q", got, want)
	}
}

func TestVerifyArchiveChecksum_Success(t *testing.T) {
	tmp := t.TempDir()
	archiveName := "backup-agent-test.tar.gz"
	archivePath := filepath.Join(tmp, archiveName)
	archiveData := []byte("dummy archive content")
	if err := os.WriteFile(archivePath, archiveData, 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	wantSum := sha256.Sum256(archiveData)
	checksumsBody := hex.EncodeToString(wantSum[:]) + "  " + archiveName + "\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(checksumsBody))
	}))
	defer srv.Close()

	if err := verifyArchiveChecksum(context.Background(), srv.URL, archiveName, archivePath); err != nil {
		t.Fatalf("verifyArchiveChecksum error = %v", err)
	}
}

func TestVerifyArchiveChecksum_MissingEntry(t *testing.T) {
	tmp := t.TempDir()
	archiveName := "backup-agent-test.tar.gz"
	archivePath := filepath.Join(tmp, archiveName)
	if err := os.WriteFile(archivePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("deadbeef  something-else.tar.gz\n"))
	}))
	defer srv.Close()

	err := verifyArchiveChecksum(context.Background(), srv.URL, archiveName, archivePath)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "checksums.txt missing entry") {
		t.Fatalf("expected missing entry error, got %q", err.Error())
	}
}

func TestVerifyArchiveChecksum_Mismatch(t *testing.T) {
	tmp := t.TempDir()
	archiveName := "backup-agent-test.tar.gz"
	archivePath := filepath.Join(tmp, archiveName)
	if err := os.WriteFile(archivePath, []byte("real"), 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0000000000000000000000000000000000000000000000000000000000000000  " + archiveName + "\n"))
	}))
	defer srv.Close()

	err := verifyArchiveChecksum(context.Background(), srv.URL, archiveName, archivePath)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected mismatch error, got %q", err.Error())
	}
}

func TestExtractExpectedBinary_TarGz(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "asset.tar.gz")
	outPath := filepath.Join(tmp, "out.bin")

	wantName := expectedBinaryName()
	wantBody := []byte("binary-content")

	if err := writeTarGzWithFile(archivePath, "nested/"+wantName, wantBody); err != nil {
		t.Fatalf("writeTarGzWithFile: %v", err)
	}
	if err := extractExpectedBinary(archivePath, outPath); err != nil {
		t.Fatalf("extractExpectedBinary: %v", err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	if string(got) != string(wantBody) {
		t.Fatalf("extracted body mismatch: got %q want %q", string(got), string(wantBody))
	}
}

func TestExtractExpectedBinary_Zip(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "asset.zip")
	outPath := filepath.Join(tmp, "out.bin")

	wantName := expectedBinaryName()
	wantBody := []byte("zip-binary")

	if err := writeZipWithFile(archivePath, "bin/"+wantName, wantBody); err != nil {
		t.Fatalf("writeZipWithFile: %v", err)
	}
	if err := extractExpectedBinary(archivePath, outPath); err != nil {
		t.Fatalf("extractExpectedBinary: %v", err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	if string(got) != string(wantBody) {
		t.Fatalf("extracted body mismatch: got %q want %q", string(got), string(wantBody))
	}
}

func TestExtractExpectedBinary_UnsupportedFormat(t *testing.T) {
	err := extractExpectedBinary("file.unknown", "out")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported archive format") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWriteFromReaderAtomic_AndCopyAndSwap(t *testing.T) {
	tmp := t.TempDir()
	dest := filepath.Join(tmp, "dest.bin")
	src := filepath.Join(tmp, "src.bin")

	if err := os.WriteFile(src, []byte("src"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := writeFromReaderAtomic(dest, bytes.NewReader([]byte("payload")), 0o755); err != nil {
		t.Fatalf("writeFromReaderAtomic: %v", err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "payload" {
		t.Fatalf("dest mismatch: %q", string(got))
	}

	staged := filepath.Join(tmp, "staged.bin")
	if err := copyFileAtomic(src, staged, 0o755); err != nil {
		t.Fatalf("copyFileAtomic: %v", err)
	}
	if got, _ := os.ReadFile(staged); string(got) != "src" {
		t.Fatalf("staged mismatch: %q", string(got))
	}

	// Swap should replace dest with staged content.
	if err := swapExecutable(dest, staged); err != nil {
		t.Fatalf("swapExecutable: %v", err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "src" {
		t.Fatalf("swapped mismatch: %q", string(got))
	}
}

func writeTarGzWithFile(path string, name string, body []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	h := &tar.Header{
		Name:     name,
		Mode:     0o755,
		Typeflag: tar.TypeReg,
		Size:     int64(len(body)),
	}
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	_, err = tw.Write(body)
	return err
}

func writeZipWithFile(path string, name string, body []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	defer zw.Close()

	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, bytes.NewReader(body))
	return err
}
