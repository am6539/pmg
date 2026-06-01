package analyzer

import (
	"context"
	"fmt"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/internal/policy"
)

// policyAnalyzer enforces the org policy cached locally from pmg-cloud heartbeats.
type policyAnalyzer struct {
	cachePath string
}

var _ PackageVersionAnalyzer = &policyAnalyzer{}

// NewPolicyAnalyzer returns an analyzer that blocks/allows by the cached org policy.
func NewPolicyAnalyzer(cachePath string) *policyAnalyzer {
	return &policyAnalyzer{cachePath: cachePath}
}

func (a *policyAnalyzer) Name() string { return "org-policy" }

func (a *policyAnalyzer) Analyze(_ context.Context, pv *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error) {
	allow := &PackageVersionAnalysisResult{PackageVersion: pv, Action: ActionAllow}

	pol, err := policy.Load(a.cachePath)
	if err != nil {
		// A corrupt cache must not break installs; treat as no policy.
		return allow, nil
	}

	eco := ecosystemString(pv.GetPackage().GetEcosystem())
	switch pol.Decision(eco, pv.GetPackage().GetName(), pv.GetVersion()) {
	case policy.DecisionBlock:
		return &PackageVersionAnalysisResult{
			PackageVersion: pv,
			Action:         ActionBlock,
			Summary:        fmt.Sprintf("blocked by organization policy: %s", pv.GetPackage().GetName()),
		}, nil
	default:
		return allow, nil
	}
}

// ecosystemString maps the protobuf ecosystem enum to the policy's lowercase string.
func ecosystemString(e packagev1.Ecosystem) string {
	switch e {
	case packagev1.Ecosystem_ECOSYSTEM_NPM:
		return "npm"
	case packagev1.Ecosystem_ECOSYSTEM_PYPI:
		return "pypi"
	default:
		return strings.ToLower(strings.TrimPrefix(e.String(), "ECOSYSTEM_"))
	}
}
