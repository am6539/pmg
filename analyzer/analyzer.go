package analyzer

import (
	"context"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

// A base interface for all analyzers
type Analyzer interface {
	Name() string
}

type Action int

const (
	ActionUnknown Action = iota
	ActionAllow
	ActionConfirm
	ActionBlock
)

type PackageVersionAnalysisResult struct {
	PackageVersion *packagev1.PackageVersion

	// Analyser specific analysis ID
	AnalysisID string

	// Reference URL for the analysis
	ReferenceURL string

	// The action to take as recommended by the analyzer
	Action Action

	// Summary of the analysis
	Summary string

	// Whether the package is flagged as malware by inference
	IsMalware bool

	// Whether the malware verdict has been verified (confirmed by a human or verification system)
	IsVerified bool

	// Degraded is true when the analyzer could not actually perform its check
	// (e.g. network failure with no usable cache). Used by the composite to
	// fail closed under paranoid mode instead of silently allowing.
	Degraded bool

	// Analyzer specific data
	Data any
}

// Contract for implementing package version specific analyzers
type PackageVersionAnalyzer interface {
	Analyzer

	Analyze(ctx context.Context, packageVersion *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error)
}
