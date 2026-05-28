package analyzer

import (
	"context"
	"sync"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

type compositeAnalyzer struct {
	analyzers []PackageVersionAnalyzer
}

var _ Analyzer = &compositeAnalyzer{}
var _ PackageVersionAnalyzer = &compositeAnalyzer{}

// NewCompositeAnalyzer runs all analyzers in parallel and returns the first
// ActionBlock result. An error from one analyzer does not prevent the others
// from running. If no analyzer blocks, ActionAllow is returned.
func NewCompositeAnalyzer(analyzers ...PackageVersionAnalyzer) *compositeAnalyzer {
	return &compositeAnalyzer{analyzers: analyzers}
}

func (c *compositeAnalyzer) Name() string {
	return "composite"
}

func (c *compositeAnalyzer) Analyze(ctx context.Context, pv *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error) {
	switch len(c.analyzers) {
	case 0:
		return &PackageVersionAnalysisResult{PackageVersion: pv, Action: ActionAllow}, nil
	case 1:
		return c.analyzers[0].Analyze(ctx, pv)
	}

	type item struct {
		res *PackageVersionAnalysisResult
		err error
	}

	// Buffered so every goroutine can write and exit without blocking,
	// even if we return early on the first ActionBlock.
	results := make(chan item, len(c.analyzers))

	var wg sync.WaitGroup
	for _, a := range c.analyzers {
		wg.Add(1)
		go func(a PackageVersionAnalyzer) {
			defer wg.Done()
			res, err := a.Analyze(ctx, pv)
			results <- item{res, err}
		}(a)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var allow *PackageVersionAnalysisResult
	var firstBlock *PackageVersionAnalysisResult
	for it := range results {
		if it.err != nil {
			continue
		}
		if it.res != nil && it.res.Action == ActionBlock {
			// Malware detection takes precedence over any other block reason
			// (e.g. dependency cooldown). Without this, a fast cooldown result
			// can win the channel race and hide the malware signal entirely.
			if it.res.IsMalware {
				return it.res, nil
			}
			if firstBlock == nil {
				firstBlock = it.res
			}
			continue
		}
		if allow == nil {
			allow = it.res
		}
	}

	if firstBlock != nil {
		return firstBlock, nil
	}
	if allow == nil {
		allow = &PackageVersionAnalysisResult{PackageVersion: pv, Action: ActionAllow}
	}
	return allow, nil
}
