package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogEcosystemScanStarted(t *testing.T) {
	s := &mockSink{}
	setGlobal(newAuditor(s))
	defer resetGlobal()

	LogEcosystemScanStarted()

	events := s.getEvents()
	require.Len(t, events, 1)
	assert.Equal(t, EventTypeEcosystemScanStarted, events[0].Type)
}

func TestLogEcosystemFinding(t *testing.T) {
	s := &mockSink{}
	setGlobal(newAuditor(s))
	defer resetGlobal()

	pv := testPackageVersion("evil-pkg", "6.6.6", "npm")
	LogEcosystemFinding(pv, []string{"/a/node_modules/evil-pkg", "/b/node_modules/evil-pkg"},
		"known malware", "https://example.com/evil-pkg", "npm uninstall evil-pkg")

	events := s.getEvents()
	require.Len(t, events, 1)
	e := events[0]
	assert.Equal(t, EventTypeEcosystemFinding, e.Type)
	assert.Equal(t, pv, e.PackageVersion)
	assert.Equal(t, []string{"/a/node_modules/evil-pkg", "/b/node_modules/evil-pkg"}, e.Details["paths"])
	assert.Equal(t, "known malware", e.Details["verdict"])
	assert.Equal(t, "https://example.com/evil-pkg", e.Details["reference_url"])
	assert.Equal(t, "npm uninstall evil-pkg", e.Details["remove_hint"])
}

func TestLogEcosystemScanCompleted(t *testing.T) {
	s := &mockSink{}
	setGlobal(newAuditor(s))
	defer resetGlobal()

	summary := EcosystemScanSummary{
		TotalPathsScanned:  120,
		UniquePackages:     40,
		FlaggedCount:       2,
		SkippedDirs:        3,
		SkippedCloudChecks: 1,
		Duration:           90 * time.Second,
	}
	LogEcosystemScanCompleted(summary)

	events := s.getEvents()
	require.Len(t, events, 1)
	assert.Equal(t, EventTypeEcosystemScanCompleted, events[0].Type)
	assert.Equal(t, 120, events[0].Details["total_paths_scanned"])
	assert.Equal(t, 2, events[0].Details["flagged_count"])
}
