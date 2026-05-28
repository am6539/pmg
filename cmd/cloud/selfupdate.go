package cloud

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
)

// SelfUpdateSilent downloads and installs the update described in resp.
// All errors are logged and swallowed — update failures must never affect
// the user's npm/pip workflow.
func SelfUpdateSilent(ctx context.Context, cfg *config.RuntimeConfig, resp HeartbeatResponse) {
	if err := selfUpdate(ctx, cfg, resp); err != nil {
		log.Warnf("PMG self-update to %s failed: %v", resp.Version, err)
		return
	}
	log.Infof("PMG self-updated to %s", resp.Version)
}

func selfUpdate(ctx context.Context, cfg *config.RuntimeConfig, resp HeartbeatResponse) error {
	if !resp.UpdateAvailable || resp.DownloadURL == "" || resp.SHA256 == "" {
		return nil
	}

	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	binaryPath, err = filepath.EvalSymlinks(binaryPath)
	if err != nil {
		return fmt.Errorf("eval symlinks: %w", err)
	}

	baseURL := strings.TrimRight(cfg.Config.AikidoIntel.BaseURL, "/")
	downloadURL := baseURL + resp.DownloadURL

	tmpPath := binaryPath + ".update"

	dlCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	if err := downloadBinary(dlCtx, cfg.Config.Cloud.APIKey, downloadURL, tmpPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("download: %w", err)
	}

	if err := verifySHA256(tmpPath, resp.SHA256); err != nil {
		os.Remove(tmpPath)
		return err
	}

	if err := os.Chmod(tmpPath, 0o755); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("chmod: %w", err)
	}

	if err := os.Rename(tmpPath, binaryPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replace binary: %w", err)
	}

	// Refresh shims so new binary is active for intercepted commands.
	cmd := exec.CommandContext(ctx, binaryPath, "setup", "install")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Warnf("pmg setup install after update: %v — %s", err, string(out))
	}
	return nil
}

func downloadBinary(ctx context.Context, apiKey, url, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

func verifySHA256(path, expectedHex string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open for verify: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash file: %w", err)
	}
	got := fmt.Sprintf("%x", h.Sum(nil))
	if got != expectedHex {
		return fmt.Errorf("sha256 mismatch: got %s want %s", got, expectedHex)
	}
	return nil
}
