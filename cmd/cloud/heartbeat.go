package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/policy"
	appVersion "github.com/safedep/pmg/internal/version"
	"github.com/spf13/cobra"
)

// HeartbeatResponse is the JSON body returned by POST /api/heartbeat.
type HeartbeatResponse struct {
	UpdateAvailable bool           `json:"update_available"`
	Version         string         `json:"version,omitempty"`
	DownloadURL     string         `json:"download_url,omitempty"`
	SHA256          string         `json:"sha256,omitempty"`
	Policy          *policy.Policy `json:"policy,omitempty"`
}

func newHeartbeatCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "heartbeat",
		Short: "Send a heartbeat ping to the enrolled PMG Cloud server",
		RunE:  runHeartbeat,
	}
}

func runHeartbeat(cmd *cobra.Command, args []string) error {
	cfg := config.Get()
	resp, err := sendHeartbeat(cmd.Context(), cfg)
	if err != nil {
		return fmt.Errorf("heartbeat failed: %w", err)
	}
	if resp.UpdateAvailable {
		log.Infof("Update available: %s — self-updating now…", resp.Version)
		SelfUpdateSilent(cmd.Context(), cfg, resp)
	}
	return nil
}

// SendHeartbeatSilent sends a heartbeat and triggers self-update if signalled.
func SendHeartbeatSilent(ctx context.Context, cfg *config.RuntimeConfig) {
	resp, err := sendHeartbeat(ctx, cfg)
	if err != nil {
		log.Debugf("Heartbeat: %v", err)
		return
	}
	if resp.UpdateAvailable {
		SelfUpdateSilent(ctx, cfg, resp)
	}
}

func sendHeartbeat(ctx context.Context, cfg *config.RuntimeConfig) (HeartbeatResponse, error) {
	apiKey := cfg.Config.Cloud.APIKey
	if apiKey == "" {
		return HeartbeatResponse{}, nil
	}
	baseURL := strings.TrimRight(cfg.Config.AikidoIntel.BaseURL, "/")
	if baseURL == "" || strings.Contains(baseURL, "aikido.dev") {
		return HeartbeatResponse{}, nil
	}

	version := appVersion.Version
	if version == "" {
		version = "dev"
	}
	body, _ := json.Marshal(map[string]string{
		"version": version,
		"os":      runtime.GOOS,
		"arch":    runtime.GOARCH,
	})

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, baseURL+"/api/heartbeat", bytes.NewReader(body))
	if err != nil {
		return HeartbeatResponse{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return HeartbeatResponse{}, fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return HeartbeatResponse{}, nil // old server — no update info
	}
	if resp.StatusCode != http.StatusOK {
		return HeartbeatResponse{}, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var hbResp HeartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&hbResp); err != nil {
		return HeartbeatResponse{}, fmt.Errorf("decode response: %w", err)
	}
	if hbResp.Policy != nil {
		if err := policy.Save(cfg.PolicyCachePath(), hbResp.Policy); err != nil {
			log.Debugf("Heartbeat: failed to cache org policy: %v", err)
		}
	}
	return hbResp, nil
}
