package ecoscan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalkFindsNodeAndPythonPackagesAcrossRoots(t *testing.T) {
	root1 := t.TempDir()
	root2 := t.TempDir()

	writePackageJSON(t, filepath.Join(root1, "projectA", "node_modules", "left-pad"), "left-pad", "1.3.0")

	distInfo := filepath.Join(root2, "venv", "lib", "site-packages", "requests-2.31.0.dist-info")
	require.NoError(t, os.MkdirAll(distInfo, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(distInfo, "METADATA"),
		[]byte("Name: requests\nVersion: 2.31.0\n"), 0o644))

	result := Walk([]string{root1, root2}, func(string) bool { return false })

	var names []string
	for _, f := range result.Found {
		names = append(names, f.Name)
	}
	assert.ElementsMatch(t, []string{"left-pad", "requests"}, names)
	assert.Equal(t, 0, result.SkippedDirs)
}

func TestWalkHonorsShouldSkip(t *testing.T) {
	root := t.TempDir()
	writePackageJSON(t, filepath.Join(root, "skip-me", "node_modules", "left-pad"), "left-pad", "1.3.0")
	writePackageJSON(t, filepath.Join(root, "keep-me", "node_modules", "right-pad"), "right-pad", "1.0.0")

	skipDir := filepath.Join(root, "skip-me")
	result := Walk([]string{root}, func(path string) bool { return path == skipDir })

	var names []string
	for _, f := range result.Found {
		names = append(names, f.Name)
	}
	assert.Equal(t, []string{"right-pad"}, names)
}

func TestWalkCountsUnreadableDirsAsSkipped(t *testing.T) {
	root := t.TempDir()
	// A root that doesn't exist at all triggers a top-level walk error.
	nonexistent := filepath.Join(root, "does-not-exist")

	result := Walk([]string{nonexistent}, func(string) bool { return false })
	assert.Empty(t, result.Found)
	assert.Equal(t, 1, result.SkippedDirs)
}
