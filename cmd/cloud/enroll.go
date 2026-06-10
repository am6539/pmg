package cloud

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"strings"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/ui"
	appVersion "github.com/safedep/pmg/internal/version"
	"github.com/spf13/cobra"
)

var (
	enrollEndpoint string
	enrollToken    string
	enrollInsecure bool
)

func newEnrollCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this machine with a self-hosted PMG Cloud server",
		RunE:  runEnroll,
	}
	cmd.Flags().StringVar(&enrollEndpoint, "endpoint", "", "PMG Cloud HTTP address (e.g. http://server:8080)")
	cmd.Flags().StringVar(&enrollToken, "token", "", "Enrollment token from PMG Cloud dashboard")
	cmd.Flags().BoolVar(&enrollInsecure, "insecure", false, "Disable TLS for gRPC (self-signed or no cert)")
	return cmd
}

type enrollRequest struct {
	Token      string `json:"token"`
	Hostname   string `json:"hostname"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	PmgVersion string `json:"pmg_version"`
	LocalIP    string `json:"local_ip"`
}

type enrollResponse struct {
	APIKey   string `json:"api_key"`
	Endpoint string `json:"endpoint"`
	Insecure bool   `json:"insecure"`
	GroupID  string `json:"group_id"`
	AgentID  string `json:"agent_id"`
}

type enrollErrorResponse struct {
	Error string `json:"error"`
}

func runEnroll(cmd *cobra.Command, args []string) error {
	if enrollEndpoint == "" {
		val, err := ui.PromptInput("PMG Cloud server (e.g. http://server:8080): ")
		if err != nil {
			return fmt.Errorf("failed to read server address: %w", err)
		}
		enrollEndpoint = strings.TrimSpace(val)
	}
	if enrollToken == "" {
		val, err := ui.PromptSecret("Enrollment token: ")
		if err != nil {
			return fmt.Errorf("failed to read enrollment token: %w", err)
		}
		enrollToken = strings.TrimSpace(val)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	version := appVersion.Version
	if version == "" {
		version = "dev"
	}

	reqBody := enrollRequest{
		Token:      enrollToken,
		Hostname:   hostname,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		PmgVersion: version,
		LocalIP:    getLocalIP(),
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to encode enrollment request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(enrollEndpoint+"/api/enroll", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to contact enrollment endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp enrollErrorResponse
		if decodeErr := json.NewDecoder(resp.Body).Decode(&errResp); decodeErr == nil && errResp.Error != "" {
			return fmt.Errorf("enrollment failed (HTTP %d): %s", resp.StatusCode, errResp.Error)
		}
		return fmt.Errorf("enrollment failed with HTTP status %d", resp.StatusCode)
	}

	var result enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode enrollment response: %w", err)
	}

	insecure := enrollInsecure || result.Insecure

	if err := config.PatchCloudConfig(result.APIKey, result.Endpoint, insecure); err != nil {
		return fmt.Errorf("failed to save enrollment config: %w", err)
	}

	if err := config.PatchRelayConfig(result.Endpoint, enrollEndpoint, insecure); err != nil {
		return fmt.Errorf("failed to save relay config: %w", err)
	}

	ui.Successf("Enrolled successfully with PMG Cloud")
	ui.Infof("Agent ID: %s", result.AgentID)
	if result.GroupID != "" {
		ui.Infof("Group ID: %s", result.GroupID)
	}
	ui.Infof("Cloud endpoint: %s", result.Endpoint)
	ui.Infof("All package checks routed through pmg-cloud (malysis + aikido relay)")

	return nil
}
