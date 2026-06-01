package analyzer

import (
	"context"
	"path/filepath"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func policyPkg(name, version string) *packagev1.PackageVersion {
	return &packagev1.PackageVersion{
		Package: &packagev1.Package{Name: name, Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM},
		Version: version,
	}
}

func writePolicy(t *testing.T, p *policy.Policy) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cloud-policy.json")
	require.NoError(t, policy.Save(path, p))
	return path
}

func TestPolicyAnalyzer_BlocksListedPackage(t *testing.T) {
	path := writePolicy(t, &policy.Policy{Blocklist: []policy.Rule{{Ecosystem: "npm", Name: "evil", Version: "*"}}})
	a := NewPolicyAnalyzer(path)
	res, err := a.Analyze(context.Background(), policyPkg("evil", "1.0.0"))
	require.NoError(t, err)
	assert.Equal(t, ActionBlock, res.Action)
}

func TestPolicyAnalyzer_AllowsUnlisted(t *testing.T) {
	path := writePolicy(t, &policy.Policy{Blocklist: []policy.Rule{{Ecosystem: "npm", Name: "evil", Version: "*"}}})
	a := NewPolicyAnalyzer(path)
	res, err := a.Analyze(context.Background(), policyPkg("safe", "1.0.0"))
	require.NoError(t, err)
	assert.Equal(t, ActionAllow, res.Action)
}

func TestPolicyAnalyzer_MissingFileAllows(t *testing.T) {
	a := NewPolicyAnalyzer(filepath.Join(t.TempDir(), "none.json"))
	res, err := a.Analyze(context.Background(), policyPkg("anything", "1.0.0"))
	require.NoError(t, err)
	assert.Equal(t, ActionAllow, res.Action)
}
