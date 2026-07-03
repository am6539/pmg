// internal/ecoscan/analyze_test.go
package ecoscan

import (
	"context"
	"sync/atomic"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAnalyzer blocks any package whose name is in blockedNames, and counts
// how many times Analyze was called (to verify capping behavior).
type fakeAnalyzer struct {
	name         string
	blockedNames map[string]bool
	callCount    atomic.Int64
}

func (f *fakeAnalyzer) Name() string { return f.name }

func (f *fakeAnalyzer) Analyze(_ context.Context, pv *packagev1.PackageVersion) (*analyzer.PackageVersionAnalysisResult, error) {
	f.callCount.Add(1)
	if f.blockedNames[pv.GetPackage().GetName()] {
		return &analyzer.PackageVersionAnalysisResult{
			PackageVersion: pv,
			Action:         analyzer.ActionBlock,
			IsMalware:      true,
			Summary:        "known malware: " + pv.GetPackage().GetName(),
			ReferenceURL:   "https://example.com/" + pv.GetPackage().GetName(),
		}, nil
	}
	return &analyzer.PackageVersionAnalysisResult{PackageVersion: pv, Action: analyzer.ActionAllow}, nil
}

func testUnique(ecosystem packagev1.Ecosystem, name, version string) UniquePackage {
	return UniquePackage{Ecosystem: ecosystem, Name: name, Version: version, Paths: []string{"/fake/" + name}}
}

func TestAnalyzeFindsAikidoBlockedPackageWithoutEscalating(t *testing.T) {
	aikido := &fakeAnalyzer{name: "aikido", blockedNames: map[string]bool{"evil-pkg": true}}
	cloud := &fakeAnalyzer{name: "cloud", blockedNames: map[string]bool{}}

	unique := []UniquePackage{testUnique(packagev1.Ecosystem_ECOSYSTEM_NPM, "evil-pkg", "6.6.6")}

	findings, stats := Analyze(context.Background(), unique, aikido, cloud, 10)

	require.Len(t, findings, 1)
	assert.Equal(t, "evil-pkg", findings[0].Package.Name)
	assert.Equal(t, "npm uninstall evil-pkg", findings[0].RemoveHint)
	assert.Equal(t, int64(0), cloud.callCount.Load(), "cloud analyzer should not be called for a package Aikido already confirmed as malware")
	assert.Equal(t, 0, stats.SkippedCloudChecks)
}

func TestAnalyzeEscalatesToCloudForPackagesAikidoDidNotBlock(t *testing.T) {
	aikido := &fakeAnalyzer{name: "aikido", blockedNames: map[string]bool{}}
	cloud := &fakeAnalyzer{name: "cloud", blockedNames: map[string]bool{"sneaky-pkg": true}}

	unique := []UniquePackage{
		testUnique(packagev1.Ecosystem_ECOSYSTEM_PYPI, "sneaky-pkg", "1.0.0"),
		testUnique(packagev1.Ecosystem_ECOSYSTEM_PYPI, "clean-pkg", "1.0.0"),
	}

	findings, stats := Analyze(context.Background(), unique, aikido, cloud, 10)

	require.Len(t, findings, 1)
	assert.Equal(t, "sneaky-pkg", findings[0].Package.Name)
	assert.Equal(t, "pip uninstall sneaky-pkg", findings[0].RemoveHint)
	assert.Equal(t, int64(2), cloud.callCount.Load())
	assert.Equal(t, 0, stats.SkippedCloudChecks)
}

func TestAnalyzeCapsCloudEscalationAndReportsSkipped(t *testing.T) {
	aikido := &fakeAnalyzer{name: "aikido", blockedNames: map[string]bool{}}
	cloud := &fakeAnalyzer{name: "cloud", blockedNames: map[string]bool{}}

	unique := []UniquePackage{
		testUnique(packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg-a", "1.0.0"),
		testUnique(packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg-b", "1.0.0"),
		testUnique(packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg-c", "1.0.0"),
	}

	_, stats := Analyze(context.Background(), unique, aikido, cloud, 1)

	assert.Equal(t, int64(1), cloud.callCount.Load())
	assert.Equal(t, 2, stats.SkippedCloudChecks)
}
