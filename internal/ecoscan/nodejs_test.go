package ecoscan

import (
	"os"
	"path/filepath"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writePackageJSON(t *testing.T, dir, name, version string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	content := `{"name":"` + name + `","version":"` + version + `"}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(content), 0o644))
}

func TestScanNodeModulesFindsDirectAndScopedPackages(t *testing.T) {
	root := t.TempDir()
	nodeModules := filepath.Join(root, "node_modules")

	writePackageJSON(t, filepath.Join(nodeModules, "left-pad"), "left-pad", "1.3.0")
	writePackageJSON(t, filepath.Join(nodeModules, "@babel", "core"), "@babel/core", "7.24.0")

	found, err := ScanNodeModules(nodeModules)
	require.NoError(t, err)
	require.Len(t, found, 2)

	names := map[string]FoundPackage{}
	for _, f := range found {
		names[f.Name] = f
	}

	require.Contains(t, names, "left-pad")
	assert.Equal(t, "1.3.0", names["left-pad"].Version)
	assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_NPM, names["left-pad"].Ecosystem)

	require.Contains(t, names, "@babel/core")
	assert.Equal(t, "7.24.0", names["@babel/core"].Version)
}

func TestScanNodeModulesRecursesIntoNestedNodeModules(t *testing.T) {
	root := t.TempDir()
	nodeModules := filepath.Join(root, "node_modules")

	writePackageJSON(t, filepath.Join(nodeModules, "outer"), "outer", "1.0.0")
	writePackageJSON(t, filepath.Join(nodeModules, "outer", "node_modules", "inner"), "inner", "2.0.0")

	found, err := ScanNodeModules(nodeModules)
	require.NoError(t, err)
	require.Len(t, found, 2)

	var names []string
	for _, f := range found {
		names = append(names, f.Name)
	}
	assert.ElementsMatch(t, []string{"outer", "inner"}, names)
}

func TestScanNodeModulesSkipsDirsWithoutPackageJSON(t *testing.T) {
	root := t.TempDir()
	nodeModules := filepath.Join(root, "node_modules")
	require.NoError(t, os.MkdirAll(filepath.Join(nodeModules, ".bin"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(nodeModules, "broken-install"), 0o755))

	found, err := ScanNodeModules(nodeModules)
	require.NoError(t, err)
	assert.Empty(t, found)
}
