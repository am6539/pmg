package analyzer

import (
	"context"
	"errors"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubAnalyzer is a test double that returns a fixed result or error.
type stubAnalyzer struct {
	name   string
	result *PackageVersionAnalysisResult
	err    error
}

func (s *stubAnalyzer) Name() string { return s.name }

func (s *stubAnalyzer) Analyze(_ context.Context, pv *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	res := *s.result
	res.PackageVersion = pv
	return &res, nil
}

func allowStub(name string) *stubAnalyzer {
	return &stubAnalyzer{name: name, result: &PackageVersionAnalysisResult{Action: ActionAllow}}
}

func blockStub(name string) *stubAnalyzer {
	return &stubAnalyzer{name: name, result: &PackageVersionAnalysisResult{Action: ActionBlock, Summary: name + " blocked"}}
}

func errStub(name string) *stubAnalyzer {
	return &stubAnalyzer{name: name, err: errors.New(name + " error")}
}

func malwareStub(name string) *stubAnalyzer {
	return &stubAnalyzer{name: name, result: &PackageVersionAnalysisResult{
		Action:    ActionBlock,
		IsMalware: true,
		Summary:   name + " malware",
	}}
}

func testPkg() *packagev1.PackageVersion {
	return &packagev1.PackageVersion{
		Package: &packagev1.Package{
			Name:      "test-pkg",
			Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
		},
		Version: "1.0.0",
	}
}

func TestComposite_Name(t *testing.T) {
	c := NewCompositeAnalyzer()
	assert.Equal(t, "composite", c.Name())
}

func TestComposite_NoAnalyzers_ReturnsAllow(t *testing.T) {
	c := NewCompositeAnalyzer()
	res, err := c.Analyze(context.Background(), testPkg())
	require.NoError(t, err)
	assert.Equal(t, ActionAllow, res.Action)
}

func TestComposite_SingleAnalyzer_PassThrough(t *testing.T) {
	c := NewCompositeAnalyzer(blockStub("only"))
	res, err := c.Analyze(context.Background(), testPkg())
	require.NoError(t, err)
	assert.Equal(t, ActionBlock, res.Action)
}

func TestComposite_AllAllow_ReturnsAllow(t *testing.T) {
	c := NewCompositeAnalyzer(allowStub("a"), allowStub("b"), allowStub("c"))
	res, err := c.Analyze(context.Background(), testPkg())
	require.NoError(t, err)
	assert.Equal(t, ActionAllow, res.Action)
}

func TestComposite_OneBlockAmongAllow_ReturnsBlock(t *testing.T) {
	c := NewCompositeAnalyzer(allowStub("a"), blockStub("blocker"), allowStub("c"))
	res, err := c.Analyze(context.Background(), testPkg())
	require.NoError(t, err)
	assert.Equal(t, ActionBlock, res.Action)
	assert.Contains(t, res.Summary, "blocker")
}

func TestComposite_ErrorFromOneDoesNotBlockOthers(t *testing.T) {
	c := NewCompositeAnalyzer(errStub("faulty"), allowStub("ok"))
	res, err := c.Analyze(context.Background(), testPkg())
	require.NoError(t, err)
	assert.Equal(t, ActionAllow, res.Action)
}

func TestComposite_ErrorFromOneBlockFromAnother_ReturnsBlock(t *testing.T) {
	c := NewCompositeAnalyzer(errStub("faulty"), blockStub("blocker"))
	res, err := c.Analyze(context.Background(), testPkg())
	require.NoError(t, err)
	assert.Equal(t, ActionBlock, res.Action)
}

func TestComposite_AllError_ReturnsAllow(t *testing.T) {
	c := NewCompositeAnalyzer(errStub("a"), errStub("b"))
	res, err := c.Analyze(context.Background(), testPkg())
	require.NoError(t, err)
	assert.Equal(t, ActionAllow, res.Action)
}

func TestComposite_MalwareTakesPrecedenceOverCooldown(t *testing.T) {
	// malware block must win over a non-malware block (e.g. cooldown) regardless
	// of goroutine scheduling order.
	for range 50 { // repeat to exercise race between goroutines
		c := NewCompositeAnalyzer(blockStub("cooldown"), malwareStub("aikido"))
		res, err := c.Analyze(context.Background(), testPkg())
		require.NoError(t, err)
		assert.Equal(t, ActionBlock, res.Action)
		assert.True(t, res.IsMalware, "malware flag must be set")
		assert.Contains(t, res.Summary, "malware")
	}
}

func TestComposite_MalwareWinsWhenMixedWithAllow(t *testing.T) {
	c := NewCompositeAnalyzer(allowStub("ok"), malwareStub("aikido"), allowStub("also-ok"))
	res, err := c.Analyze(context.Background(), testPkg())
	require.NoError(t, err)
	assert.Equal(t, ActionBlock, res.Action)
	assert.True(t, res.IsMalware)
}

func TestComposite_PackageVersionPropagated(t *testing.T) {
	pv := testPkg()
	c := NewCompositeAnalyzer(allowStub("a"))
	res, err := c.Analyze(context.Background(), pv)
	require.NoError(t, err)
	assert.Equal(t, pv, res.PackageVersion)
}
