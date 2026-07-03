package ecoscan

import (
	"os"
	"path/filepath"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePackageMetadataReadsNameAndVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "METADATA")
	content := "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\nSummary: HTTP library\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	name, version, err := ParsePackageMetadata(path)
	require.NoError(t, err)
	assert.Equal(t, "requests", name)
	assert.Equal(t, "2.31.0", version)
}

func TestParsePackageMetadataMissingFile(t *testing.T) {
	_, _, err := ParsePackageMetadata(filepath.Join(t.TempDir(), "does-not-exist"))
	assert.Error(t, err)
}

func TestDetectPythonPackageDistInfo(t *testing.T) {
	dir := t.TempDir()
	distInfo := filepath.Join(dir, "requests-2.31.0.dist-info")
	require.NoError(t, os.MkdirAll(distInfo, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(distInfo, "METADATA"),
		[]byte("Name: requests\nVersion: 2.31.0\n"), 0o644))

	pkg, ok, err := DetectPythonPackage(distInfo)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_PYPI, pkg.Ecosystem)
	assert.Equal(t, "requests", pkg.Name)
	assert.Equal(t, "2.31.0", pkg.Version)
	assert.Equal(t, distInfo, pkg.Path)
}

func TestDetectPythonPackageEggInfo(t *testing.T) {
	dir := t.TempDir()
	eggInfo := filepath.Join(dir, "six.egg-info")
	require.NoError(t, os.MkdirAll(eggInfo, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(eggInfo, "PKG-INFO"),
		[]byte("Name: six\nVersion: 1.16.0\n"), 0o644))

	pkg, ok, err := DetectPythonPackage(eggInfo)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "six", pkg.Name)
	assert.Equal(t, "1.16.0", pkg.Version)
}

func TestDetectPythonPackageIgnoresUnrelatedDir(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "some-folder")
	require.NoError(t, os.MkdirAll(other, 0o755))

	_, ok, err := DetectPythonPackage(other)
	require.NoError(t, err)
	assert.False(t, ok)
}
