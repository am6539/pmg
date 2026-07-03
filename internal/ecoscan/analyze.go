// internal/ecoscan/analyze.go
package ecoscan

import (
	"context"
	"fmt"
	"sync"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
)

// DefaultMaxCloudCalls bounds how many unique packages per scan are escalated
// to the SafeDep Cloud analyzer, to avoid overwhelming it on a machine with a
// very large number of unique installed packages. Packages beyond the cap
// are counted in AnalyzeStats.SkippedCloudChecks rather than silently dropped.
const DefaultMaxCloudCalls = 2000

// cloudAnalysisWorkers bounds concurrent SafeDep Cloud calls during phase 2.
const cloudAnalysisWorkers = 5

// Finding is a single package confirmed malicious during an ecosystem scan.
type Finding struct {
	Package      UniquePackage
	Verdict      string
	ReferenceURL string
	RemoveHint   string
}

// AnalyzeStats carries counters that aren't part of any single Finding.
type AnalyzeStats struct {
	SkippedCloudChecks int
}

// Analyze runs a two-phase check over unique packages:
//
//  1. Every package against aikido (an offline, disk-cached blocklist feed).
//     Aikido can only confirm "known malicious" — it never confirms a
//     package as clean — so packages it blocks are reported immediately
//     without further checks.
//  2. Every package Aikido did NOT block is a candidate for cloudAnalyzer
//     (SafeDep Cloud), bounded by maxCloudCalls. Candidates beyond the cap
//     are counted in AnalyzeStats.SkippedCloudChecks, never silently dropped.
func Analyze(ctx context.Context, unique []UniquePackage, aikido, cloudAnalyzer analyzer.PackageVersionAnalyzer, maxCloudCalls int) ([]Finding, AnalyzeStats) {
	var findings []Finding
	var phase2Candidates []UniquePackage

	for _, pkg := range unique {
		res, err := aikido.Analyze(ctx, toPackageVersion(pkg))
		if err == nil && res.Action == analyzer.ActionBlock && res.IsMalware {
			findings = append(findings, toFinding(pkg, res))
			continue
		}
		phase2Candidates = append(phase2Candidates, pkg)
	}

	stats := AnalyzeStats{}
	if len(phase2Candidates) > maxCloudCalls {
		stats.SkippedCloudChecks = len(phase2Candidates) - maxCloudCalls
		phase2Candidates = phase2Candidates[:maxCloudCalls]
	}

	findings = append(findings, analyzeCloudPhase(ctx, phase2Candidates, cloudAnalyzer)...)
	return findings, stats
}

func analyzeCloudPhase(ctx context.Context, candidates []UniquePackage, cloudAnalyzer analyzer.PackageVersionAnalyzer) []Finding {
	if len(candidates) == 0 {
		return nil
	}

	jobs := make(chan UniquePackage, len(candidates))
	for _, pkg := range candidates {
		jobs <- pkg
	}
	close(jobs)

	results := make(chan Finding, len(candidates))
	var wg sync.WaitGroup
	for i := 0; i < cloudAnalysisWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pkg := range jobs {
				res, err := cloudAnalyzer.Analyze(ctx, toPackageVersion(pkg))
				if err != nil || res.Action != analyzer.ActionBlock || !res.IsMalware {
					continue
				}
				results <- toFinding(pkg, res)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var findings []Finding
	for f := range results {
		findings = append(findings, f)
	}
	return findings
}

func toPackageVersion(pkg UniquePackage) *packagev1.PackageVersion {
	return &packagev1.PackageVersion{
		Package: &packagev1.Package{Name: pkg.Name, Ecosystem: pkg.Ecosystem},
		Version: pkg.Version,
	}
}

func toFinding(pkg UniquePackage, res *analyzer.PackageVersionAnalysisResult) Finding {
	return Finding{
		Package:      pkg,
		Verdict:      res.Summary,
		ReferenceURL: res.ReferenceURL,
		RemoveHint:   removeHint(pkg),
	}
}

func removeHint(pkg UniquePackage) string {
	switch pkg.Ecosystem {
	case packagev1.Ecosystem_ECOSYSTEM_NPM:
		return fmt.Sprintf("npm uninstall %s", pkg.Name)
	case packagev1.Ecosystem_ECOSYSTEM_PYPI:
		return fmt.Sprintf("pip uninstall %s", pkg.Name)
	default:
		return ""
	}
}
