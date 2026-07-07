// cmd/cloud/ecoscan_report.go
package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/ecoscan"
)

// scanPackagePayload is the wire shape of a single installed package (clean or flagged)
// sent to POST /api/scan-report.
type scanPackagePayload struct {
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Paths     []string `json:"paths"`
}

// scanFindingPayload is the wire shape of a single ecosystem scan finding
// sent to POST /api/scan-report.
type scanFindingPayload struct {
	Ecosystem    string   `json:"ecosystem"`
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Verdict      string   `json:"verdict"`
	ReferenceURL string   `json:"reference_url"`
	Paths        []string `json:"paths"`
	RemoveHint   string   `json:"remove_hint"`
}

// scanSummaryPayload is the wire shape of the scan summary sent to
// POST /api/scan-report.
type scanSummaryPayload struct {
	TotalPathsScanned  int     `json:"total_paths_scanned"`
	UniquePackages     int     `json:"unique_packages"`
	FlaggedCount       int     `json:"flagged_count"`
	SkippedDirs        int     `json:"skipped_dirs"`
	SkippedCloudChecks int     `json:"skipped_cloud_checks"`
	DurationSeconds    float64 `json:"duration_seconds"`
}

// scanReportPayload is the full body of POST /api/scan-report.
type scanReportPayload struct {
	Status   string               `json:"status"`
	Findings []scanFindingPayload `json:"findings,omitempty"`
	Packages []scanPackagePayload `json:"packages,omitempty"`
	Summary  *scanSummaryPayload  `json:"summary,omitempty"`
}

// toScanReportPayload converts an ecoscan.Report into the wire payload for a
// "completed" scan-report POST.
func toScanReportPayload(status string, report ecoscan.Report) scanReportPayload {
	findings := make([]scanFindingPayload, 0, len(report.Findings))
	for _, f := range report.Findings {
		findings = append(findings, scanFindingPayload{
			Ecosystem:    ecoscan.EcosystemName(f.Package.Ecosystem),
			Name:         f.Package.Name,
			Version:      f.Package.Version,
			Verdict:      f.Verdict,
			ReferenceURL: f.ReferenceURL,
			Paths:        f.Package.Paths,
			RemoveHint:   f.RemoveHint,
		})
	}

	flagged := make(map[string]struct{}, len(report.Findings))
	for _, f := range report.Findings {
		flagged[ecoscan.EcosystemName(f.Package.Ecosystem)+"/"+f.Package.Name+"/"+f.Package.Version] = struct{}{}
	}
	packages := make([]scanPackagePayload, 0, len(report.Packages))
	for _, p := range report.Packages {
		key := ecoscan.EcosystemName(p.Ecosystem) + "/" + p.Name + "/" + p.Version
		if _, isFlagged := flagged[key]; isFlagged {
			continue
		}
		packages = append(packages, scanPackagePayload{
			Ecosystem: ecoscan.EcosystemName(p.Ecosystem),
			Name:      p.Name,
			Version:   p.Version,
			Paths:     p.Paths,
		})
	}

	return scanReportPayload{
		Status:   status,
		Findings: findings,
		Packages: packages,
		Summary: &scanSummaryPayload{
			TotalPathsScanned:  report.Summary.TotalPathsScanned,
			UniquePackages:     report.Summary.UniquePackages,
			FlaggedCount:       report.Summary.FlaggedCount,
			SkippedDirs:        report.Summary.SkippedDirs,
			SkippedCloudChecks: report.Summary.SkippedCloudChecks,
			DurationSeconds:    report.Summary.Duration.Seconds(),
		},
	}
}

// postScanReport sends a scan-report payload to pmg-cloud. It mirrors
// sendHeartbeat's URL/auth resolution exactly and is best-effort: failures
// are logged, never returned, since a scan-report POST failing must not fail
// or abort the scan itself.
func postScanReport(ctx context.Context, cfg *config.RuntimeConfig, payload scanReportPayload) {
	apiKey := cfg.Config.Cloud.APIKey
	if apiKey == "" {
		return
	}
	baseURL := strings.TrimRight(cfg.Config.AikidoIntel.BaseURL, "/")
	if baseURL == "" || strings.Contains(baseURL, "aikido.dev") {
		return
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Warnf("ecoscan: failed to encode scan-report payload: %v", err)
		return
	}

	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, baseURL+"/api/scan-report", bytes.NewReader(body))
	if err != nil {
		log.Warnf("ecoscan: failed to build scan-report request: %v", err)
		return
	}
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Warnf("ecoscan: failed to send scan-report (status=%s): %v", payload.Status, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		log.Warnf("ecoscan: scan-report (status=%s) got unexpected response %d", payload.Status, resp.StatusCode)
	}
}

// buildEcoscanAnalyzers constructs the two analyzers ecoscan.Run needs:
// an Aikido-only analyzer for the offline first pass, and a
// malysis+policy composite (no Aikido) for the capped cloud escalation pass.
func buildEcoscanAnalyzers(cfg *config.RuntimeConfig) (aikido, cloudAnalyzer analyzer.PackageVersionAnalyzer, err error) {
	aikidoAnalyzer, err := analyzer.NewAikidoIntelAnalyzer(analyzer.AikidoIntelAnalyzerConfig{
		BaseURL:     cfg.Config.AikidoIntel.BaseURL,
		CacheDir:    cfg.AikidoCacheDir(),
		CacheTTL:    cfg.Config.AikidoIntel.CacheTTL,
		HTTPTimeout: cfg.Config.AikidoIntel.RequestTimeout,
	})
	if err != nil {
		return nil, nil, err
	}

	malysis, err := analyzer.NewMalysisQueryAnalyzer(analyzer.MalysisQueryAnalyzerConfig{
		Addr:     cfg.Config.Malysis.Addr,
		Insecure: cfg.Config.Malysis.Insecure,
	})
	if err != nil {
		return nil, nil, err
	}

	policyAnalyzer := analyzer.NewPolicyAnalyzer(cfg.PolicyCachePath())
	cloud := analyzer.NewCompositeAnalyzer(malysis, policyAnalyzer)

	return aikidoAnalyzer, cloud, nil
}

// runEcosystemScanIfRequested is called after every heartbeat response. If
// requested is false, it does nothing. Otherwise it acquires the ecoscan
// lock (skipping this cycle if a scan is already running), runs a full scan,
// and reports progress/results to pmg-cloud.
func runEcosystemScanIfRequested(ctx context.Context, cfg *config.RuntimeConfig, requested bool) {
	if !requested {
		return
	}

	release, ok, err := ecoscan.AcquireLock(cfg.EcoScanLockPath())
	if err != nil {
		log.Warnf("ecoscan: failed to acquire lock: %v", err)
		return
	}
	if !ok {
		log.Debugf("ecoscan: scan already in progress, skipping this cycle")
		return
	}
	defer release()

	postScanReport(ctx, cfg, scanReportPayload{Status: "started"})

	aikido, cloudAnalyzer, err := buildEcoscanAnalyzers(cfg)
	if err != nil {
		log.Warnf("ecoscan: failed to build analyzers: %v", err)
		return
	}

	roots, err := ecoscan.Roots()
	if err != nil {
		log.Warnf("ecoscan: failed to enumerate scan roots: %v", err)
		return
	}

	report, err := ecoscan.Run(ctx, roots, aikido, cloudAnalyzer)
	if err != nil {
		log.Warnf("ecoscan: scan failed: %v", err)
		return
	}

	postScanReport(ctx, cfg, toScanReportPayload("completed", report))
}
