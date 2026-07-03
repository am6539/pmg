// internal/ecoscan/dedupe_test.go
package ecoscan

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDedupeCollapsesSameEcosystemNameVersion(t *testing.T) {
	found := []FoundPackage{
		{Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM, Name: "left-pad", Version: "1.0.0", Path: "/a/node_modules/left-pad"},
		{Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM, Name: "left-pad", Version: "1.0.0", Path: "/b/node_modules/left-pad"},
		{Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM, Name: "left-pad", Version: "2.0.0", Path: "/c/node_modules/left-pad"},
		{Ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI, Name: "requests", Version: "2.31.0", Path: "/d/site-packages/requests-2.31.0.dist-info"},
	}

	unique := Dedupe(found)
	require.Len(t, unique, 3)

	assert.Equal(t, "left-pad", unique[0].Name)
	assert.Equal(t, "1.0.0", unique[0].Version)
	assert.ElementsMatch(t, []string{"/a/node_modules/left-pad", "/b/node_modules/left-pad"}, unique[0].Paths)

	assert.Equal(t, "2.0.0", unique[1].Version)
	assert.Equal(t, []string{"/c/node_modules/left-pad"}, unique[1].Paths)

	assert.Equal(t, packagev1.Ecosystem_ECOSYSTEM_PYPI, unique[2].Ecosystem)
	assert.Equal(t, "requests", unique[2].Name)
}

func TestDedupeEmptyInput(t *testing.T) {
	assert.Empty(t, Dedupe(nil))
}
