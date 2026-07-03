// internal/ecoscan/scan_test.go
package ecoscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunEndToEndFindsAndReportsMalware(t *testing.T) {
	root := t.TempDir()
	writePackageJSON(t, filepath.Join(root, "app", "node_modules", "evil-pkg"), "evil-pkg", "6.6.6")
	writePackageJSON(t, filepath.Join(root, "app", "node_modules", "clean-pkg"), "clean-pkg", "1.0.0")

	aikido := &fakeAnalyzer{name: "aikido", blockedNames: map[string]bool{"evil-pkg": true}}
	cloud := &fakeAnalyzer{name: "cloud", blockedNames: map[string]bool{}}

	report, err := Run(context.Background(), []string{root}, aikido, cloud)
	require.NoError(t, err)

	require.Len(t, report.Findings, 1)
	assert.Equal(t, "evil-pkg", report.Findings[0].Package.Name)
	assert.Equal(t, 2, report.Summary.UniquePackages)
	assert.Equal(t, 1, report.Summary.FlaggedCount)
	assert.Equal(t, int64(1), cloud.callCount.Load(), "only clean-pkg should escalate to cloud")
}

func TestRunWithNoPackagesFound(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(root, 0o755))

	aikido := &fakeAnalyzer{name: "aikido", blockedNames: map[string]bool{}}
	cloud := &fakeAnalyzer{name: "cloud", blockedNames: map[string]bool{}}

	report, err := Run(context.Background(), []string{root}, aikido, cloud)
	require.NoError(t, err)
	assert.Empty(t, report.Findings)
	assert.Equal(t, 0, report.Summary.UniquePackages)
}
