package cloud

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/spf13/cobra"
)

func newHeartbeatCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "heartbeat",
		Short: "Send a heartbeat ping to the enrolled PMG Cloud server",
		RunE:  runHeartbeat,
	}
}

func runHeartbeat(cmd *cobra.Command, args []string) error {
	cfg := config.Get()
	if err := sendHeartbeat(cmd.Context(), cfg); err != nil {
		return fmt.Errorf("heartbeat failed: %w", err)
	}
	return nil
}

// SendHeartbeatSilent sends a heartbeat and logs (but does not return) any error.
// Used by the background sync child so a dead server does not fail the whole sync.
func SendHeartbeatSilent(ctx context.Context, cfg *config.RuntimeConfig) {
	if err := sendHeartbeat(ctx, cfg); err != nil {
		log.Debugf("Heartbeat: %v", err)
	}
}

func sendHeartbeat(ctx context.Context, cfg *config.RuntimeConfig) error {
	apiKey := cfg.Config.Cloud.APIKey
	if apiKey == "" {
		return nil // not enrolled with a self-hosted server; skip silently
	}

	// AikidoIntel.BaseURL stores the enrolled HTTP server URL (set by PatchRelayConfig).
	baseURL := strings.TrimRight(cfg.Config.AikidoIntel.BaseURL, "/")
	if baseURL == "" || strings.Contains(baseURL, "aikido.dev") {
		return nil // not pointed at a self-hosted pmg-cloud; skip
	}

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, baseURL+"/api/heartbeat", nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}
