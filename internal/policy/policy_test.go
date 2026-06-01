package policy

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecision_NoPolicyAllows(t *testing.T) {
	p := &Policy{}
	assert.Equal(t, DecisionNone, p.Decision("npm", "anything", "1.0.0"))
}

func TestDecision_BlocklistExactVersion(t *testing.T) {
	p := &Policy{Blocklist: []Rule{{Ecosystem: "npm", Name: "evil", Version: "1.0.0"}}}
	assert.Equal(t, DecisionBlock, p.Decision("npm", "evil", "1.0.0"))
	assert.Equal(t, DecisionNone, p.Decision("npm", "evil", "2.0.0"))
}

func TestDecision_BlocklistWildcard(t *testing.T) {
	p := &Policy{Blocklist: []Rule{{Ecosystem: "npm", Name: "evil", Version: "*"}}}
	assert.Equal(t, DecisionBlock, p.Decision("npm", "evil", "9.9.9"))
}

func TestDecision_EcosystemAnyMatches(t *testing.T) {
	p := &Policy{Blocklist: []Rule{{Ecosystem: "", Name: "evil", Version: "*"}}}
	assert.Equal(t, DecisionBlock, p.Decision("pypi", "evil", "1.0.0"))
}

func TestDecision_AllowlistWins(t *testing.T) {
	p := &Policy{
		Blocklist: []Rule{{Ecosystem: "npm", Name: "thing", Version: "*"}},
		Allowlist: []Rule{{Ecosystem: "npm", Name: "thing", Version: "*"}},
	}
	assert.Equal(t, DecisionAllow, p.Decision("npm", "thing", "1.0.0"))
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cloud-policy.json")
	in := &Policy{Blocklist: []Rule{{Ecosystem: "npm", Name: "evil", Version: "*"}}}
	require.NoError(t, Save(path, in))

	out, err := Load(path)
	require.NoError(t, err)
	require.Len(t, out.Blocklist, 1)
	assert.Equal(t, "evil", out.Blocklist[0].Name)
}

func TestLoad_MissingFileReturnsEmpty(t *testing.T) {
	out, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	require.NoError(t, err)
	assert.Empty(t, out.Blocklist)
}
