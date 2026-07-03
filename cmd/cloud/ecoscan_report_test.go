package cloud

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/ecoscan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostScanReportSendsStartedStatus(t *testing.T) {
	var received scanReportPayload
	srv := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/scan-report", r.URL.Path)
		require.Equal(t, "test-api-key", r.Header.Get("Authorization"))
		require.NoError(t, json.NewDecoder(r.Body).Decode(&received))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.RuntimeConfig{}
	cfg.Config.Cloud.APIKey = "test-api-key"
	cfg.Config.AikidoIntel.BaseURL = srv.URL

	postScanReport(t.Context(), cfg, scanReportPayload{Status: "started"})

	assert.Equal(t, "started", received.Status)
	assert.Nil(t, received.Findings)
}

func TestPostScanReportSendsCompletedStatusWithFindings(t *testing.T) {
	var received scanReportPayload
	srv := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&received))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.RuntimeConfig{}
	cfg.Config.Cloud.APIKey = "test-api-key"
	cfg.Config.AikidoIntel.BaseURL = srv.URL

	report := ecoscan.Report{
		Findings: []ecoscan.Finding{{
			Package:      ecoscan.UniquePackage{Name: "evil-pkg", Version: "6.6.6", Paths: []string{"/a"}},
			Verdict:      "known malware",
			ReferenceURL: "https://example.com/evil-pkg",
			RemoveHint:   "npm uninstall evil-pkg",
		}},
	}

	postScanReport(t.Context(), cfg, toScanReportPayload("completed", report))

	require.Len(t, received.Findings, 1)
	assert.Equal(t, "evil-pkg", received.Findings[0].Name)
	assert.Equal(t, "completed", received.Status)
}

func TestPostScanReportSkipsWhenNoAPIKey(t *testing.T) {
	cfg := &config.RuntimeConfig{}
	// No panic, no request attempted — nothing to assert on beyond "it returns".
	postScanReport(t.Context(), cfg, scanReportPayload{Status: "started"})
}

func TestHeartbeatResponseDecodesScanRequested(t *testing.T) {
	var resp HeartbeatResponse
	require.NoError(t, json.Unmarshal([]byte(`{"scan_requested": true}`), &resp))
	assert.True(t, resp.ScanRequested)
}
