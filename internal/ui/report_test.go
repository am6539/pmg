package ui

import (
	"testing"

	"github.com/safedep/pmg/analyzer"
)

func TestSplitBlockedByMalware(t *testing.T) {
	malwarePkg := &analyzer.PackageVersionAnalysisResult{IsMalware: true, Summary: "known malware"}
	policyPkg := &analyzer.PackageVersionAnalysisResult{IsMalware: false, Summary: "blocked by organization policy: handlebars"}

	malware, policy := splitBlockedByMalware([]*analyzer.PackageVersionAnalysisResult{malwarePkg, policyPkg})

	if len(malware) != 1 || malware[0] != malwarePkg {
		t.Fatalf("expected malwarePkg in malware slice, got %+v", malware)
	}
	if len(policy) != 1 || policy[0] != policyPkg {
		t.Fatalf("expected policyPkg in policy slice, got %+v", policy)
	}
}

func TestSplitBlockedByMalwareEmpty(t *testing.T) {
	malware, policy := splitBlockedByMalware(nil)
	if len(malware) != 0 || len(policy) != 0 {
		t.Fatalf("expected both slices empty, got malware=%v policy=%v", malware, policy)
	}
}
