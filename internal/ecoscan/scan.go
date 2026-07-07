// internal/ecoscan/scan.go
package ecoscan

import (
	"context"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/internal/audit"
)

// Report is the result of a completed ecosystem scan, ready to be posted to pmg-cloud.
type Report struct {
	Findings []Finding
	Packages []UniquePackage // all unique packages discovered, including clean ones
	Summary  audit.EcosystemScanSummary
}

// Run performs one full ecosystem scan pass over roots: walk for installed
// packages, dedupe, run two-phase analysis, and log to the local audit trail.
// It does not talk to pmg-cloud — the caller (cmd/cloud) posts the returned
// Report to the scan-report endpoint.
func Run(ctx context.Context, roots []string, aikido, cloudAnalyzer analyzer.PackageVersionAnalyzer) (Report, error) {
	start := time.Now()
	audit.LogEcosystemScanStarted()

	walkResult := Walk(roots, ShouldSkipDir)
	unique := Dedupe(walkResult.Found)
	findings, stats := Analyze(ctx, unique, aikido, cloudAnalyzer, DefaultMaxCloudCalls)

	for _, f := range findings {
		audit.LogEcosystemFinding(toPackageVersion(f.Package), f.Package.Paths, f.Verdict, f.ReferenceURL, f.RemoveHint)
	}

	summary := audit.EcosystemScanSummary{
		TotalPathsScanned:  len(walkResult.Found),
		UniquePackages:     len(unique),
		FlaggedCount:       len(findings),
		SkippedDirs:        walkResult.SkippedDirs,
		SkippedCloudChecks: stats.SkippedCloudChecks,
		Duration:           time.Since(start),
	}
	audit.LogEcosystemScanCompleted(summary)

	log.Infof("ecosystem scan complete: %d unique packages, %d flagged, %d dirs skipped, %d cloud checks skipped",
		summary.UniquePackages, summary.FlaggedCount, summary.SkippedDirs, summary.SkippedCloudChecks)

	return Report{Findings: findings, Packages: unique, Summary: summary}, nil
}
