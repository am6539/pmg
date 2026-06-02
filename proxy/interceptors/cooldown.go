package interceptors

import (
	"context"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/internal/audit"
)

// newCooldownPV builds a PackageVersion for the given ecosystem/name/version.
func newCooldownPV(ecosystem packagev1.Ecosystem, name, version string) *packagev1.PackageVersion {
	pv := &packagev1.PackageVersion{}
	pv.SetPackage(&packagev1.Package{})
	pv.GetPackage().SetName(name)
	pv.GetPackage().SetEcosystem(ecosystem)
	pv.SetVersion(version)
	return pv
}

// malwareInCooldownWindow returns, for each version still inside the cooldown
// window, the malware analysis result when the local feed flags it as malware.
// It performs no audit side effects so it can be unit-tested in isolation.
// A nil checker yields an empty map.
func malwareInCooldownWindow(checker analyzer.PackageVersionAnalyzer, ecosystem packagev1.Ecosystem, name string, dates map[string]time.Time, cooldownDays int) map[string]*analyzer.PackageVersionAnalysisResult {
	out := map[string]*analyzer.PackageVersionAnalysisResult{}
	if checker == nil {
		return out
	}
	for version, publishDate := range dates {
		if within, _, _ := cooldownIsWithinWindow(publishDate, cooldownDays); !within {
			continue
		}
		res, err := checker.Analyze(context.Background(), newCooldownPV(ecosystem, name, version))
		if err != nil || res == nil || !res.IsMalware {
			continue
		}
		out[version] = res
	}
	return out
}

// cooldownIsWithinWindow reports whether a version published at publishDate is still
// within the cooldown window of cooldownDays. Returns withinCooldown, daysSincePublish,
// and daysRemaining.
func cooldownIsWithinWindow(publishDate time.Time, cooldownDays int) (withinCooldown bool, daysSincePublish int, daysRemaining int) {
	daysSincePublish = int(time.Since(publishDate).Hours() / 24)
	if daysSincePublish < 0 {
		daysSincePublish = 0
	}
	daysRemaining = cooldownDays - daysSincePublish
	if daysRemaining < 0 {
		daysRemaining = 0
	}
	return daysSincePublish < cooldownDays, daysSincePublish, daysRemaining
}

// cooldownOldestVersion returns the version with the earliest publish date.
// When all versions are in cooldown, this is the one closest to exiting the window.
func cooldownOldestVersion(dates map[string]time.Time) (string, time.Time) {
	var oldest string
	var oldestTime time.Time
	for version, publishDate := range dates {
		if oldestTime.IsZero() || publishDate.Before(oldestTime) {
			oldest = version
			oldestTime = publishDate
		}
	}
	return oldest, oldestTime
}

// recordCooldownStats records a cooldown block event. When all versions are blocked
// (remaining == 0), it reports the oldest version (closest to exiting cooldown).
// Otherwise, if a pinned version was stripped, it reports that specific version.
func recordCooldownStats(statsCollector *AnalysisStatsCollector, malwareChecker analyzer.PackageVersionAnalyzer, ecosystem packagev1.Ecosystem, packageName string, pinnedVersion string, dates map[string]time.Time, remaining int, cooldownDays int) {
	if statsCollector == nil {
		return
	}

	// A version can be both too new (cooldown) and known malware. Surface such
	// versions as MALWARE so the dashboard never reports a blacklisted version
	// as a clean cooldown block. The local feed lookup is version-exact.
	malwareVersions := malwareInCooldownWindow(malwareChecker, ecosystem, packageName, dates, cooldownDays)
	for version, res := range malwareVersions {
		audit.LogMalwareBlocked(newCooldownPV(ecosystem, packageName, version),
			res.Summary, res.AnalysisID, res.ReferenceURL, res.IsMalware, res.IsVerified)
	}

	logCooldown := func(version string, publishDate time.Time, daysAgo, daysLeft int) {
		if _, isMalware := malwareVersions[version]; isMalware {
			return // already surfaced as malware; do not also log a clean cooldown
		}
		statsCollector.RecordCooldownBlocked(packageName, version, publishDate, daysAgo, daysLeft, cooldownDays)
		audit.LogDependencyCooldown(newCooldownPV(ecosystem, packageName, version), publishDate, cooldownDays, daysAgo, daysLeft)
	}

	if remaining == 0 {
		oldestVer, oldestDate := cooldownOldestVersion(dates)
		if oldestVer != "" {
			_, daysAgo, daysLeft := cooldownIsWithinWindow(oldestDate, cooldownDays)
			logCooldown(oldestVer, oldestDate, daysAgo, daysLeft)
		}
	} else if pinnedVersion != "" {
		if pinnedDate, ok := dates[pinnedVersion]; ok {
			if withinCooldown, daysAgo, daysLeft := cooldownIsWithinWindow(pinnedDate, cooldownDays); withinCooldown {
				logCooldown(pinnedVersion, pinnedDate, daysAgo, daysLeft)
			}
		}
	}
}

// cooldownLatestEligibleVersion returns the most recently published version not in tooNew.
func cooldownLatestEligibleVersion(dates map[string]time.Time, tooNew map[string]bool) string {
	var latest string
	var latestTime time.Time
	for version, publishDate := range dates {
		if tooNew[version] {
			continue
		}
		if publishDate.After(latestTime) {
			latest = version
			latestTime = publishDate
		}
	}
	return latest
}
