package interceptors

import (
	"context"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/stretchr/testify/assert"
)

// fakeMalwareChecker flags the configured set of versions as malware.
type fakeMalwareChecker struct {
	malwareVersions map[string]bool
}

func (f *fakeMalwareChecker) Name() string { return "fake" }

func (f *fakeMalwareChecker) Analyze(_ context.Context, pv *packagev1.PackageVersion) (*analyzer.PackageVersionAnalysisResult, error) {
	if f.malwareVersions[pv.GetVersion()] {
		return &analyzer.PackageVersionAnalysisResult{
			PackageVersion: pv,
			Action:         analyzer.ActionBlock,
			IsMalware:      true,
			IsVerified:     true,
			Summary:        "MALWARE",
		}, nil
	}
	return &analyzer.PackageVersionAnalysisResult{PackageVersion: pv, Action: analyzer.ActionAllow}, nil
}

func TestMalwareInCooldownWindow_FlagsOnlyInWindowMalware(t *testing.T) {
	now := time.Now()
	dates := map[string]time.Time{
		"3.6.1": now.Add(-1 * 24 * time.Hour),  // in cooldown window, malware
		"3.6.0": now.Add(-30 * 24 * time.Hour), // outside window, malware (ignored)
		"3.5.0": now.Add(-2 * 24 * time.Hour),  // in window, clean
	}
	checker := &fakeMalwareChecker{malwareVersions: map[string]bool{"3.6.1": true, "3.6.0": true}}

	got := malwareInCooldownWindow(checker, packagev1.Ecosystem_ECOSYSTEM_NPM, "@redhat-cloud-services/types", dates, 5)

	assert.Len(t, got, 1)
	assert.Contains(t, got, "3.6.1")
	assert.NotContains(t, got, "3.6.0") // outside cooldown window
	assert.NotContains(t, got, "3.5.0") // clean
}

func TestMalwareInCooldownWindow_NilCheckerEmpty(t *testing.T) {
	dates := map[string]time.Time{"1.0.0": time.Now()}
	assert.Empty(t, malwareInCooldownWindow(nil, packagev1.Ecosystem_ECOSYSTEM_NPM, "x", dates, 5))
}

func TestCooldownIsWithinWindow(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour

	tests := []struct {
		name                 string
		publishDate          time.Time
		cooldownDays         int
		wantWithinCooldown   bool
		wantDaysSincePublish int
		wantDaysRemaining    int
	}{
		{
			name:                 "published today with 30 day cooldown",
			publishDate:          now,
			cooldownDays:         30,
			wantWithinCooldown:   true,
			wantDaysSincePublish: 0,
			wantDaysRemaining:    30,
		},
		{
			name:                 "published exactly at cooldown boundary",
			publishDate:          now.Add(-30 * day),
			cooldownDays:         30,
			wantWithinCooldown:   false,
			wantDaysSincePublish: 30,
			wantDaysRemaining:    0,
		},
		{
			name:                 "published one day before cooldown expires",
			publishDate:          now.Add(-29 * day),
			cooldownDays:         30,
			wantWithinCooldown:   true,
			wantDaysSincePublish: 29,
			wantDaysRemaining:    1,
		},
		{
			name:                 "published well beyond cooldown",
			publishDate:          now.Add(-365 * day),
			cooldownDays:         30,
			wantWithinCooldown:   false,
			wantDaysSincePublish: 365,
			wantDaysRemaining:    0,
		},
		{
			name:                 "zero cooldown days",
			publishDate:          now,
			cooldownDays:         0,
			wantWithinCooldown:   false,
			wantDaysSincePublish: 0,
			wantDaysRemaining:    0,
		},
		{
			name:                 "future publish date clamped to zero days",
			publishDate:          now.Add(5 * day),
			cooldownDays:         30,
			wantWithinCooldown:   true,
			wantDaysSincePublish: 0,
			wantDaysRemaining:    30,
		},
		{
			name:                 "one day cooldown with publish today",
			publishDate:          now,
			cooldownDays:         1,
			wantWithinCooldown:   true,
			wantDaysSincePublish: 0,
			wantDaysRemaining:    1,
		},
		{
			name:                 "one day cooldown with publish yesterday",
			publishDate:          now.Add(-1 * day),
			cooldownDays:         1,
			wantWithinCooldown:   false,
			wantDaysSincePublish: 1,
			wantDaysRemaining:    0,
		},
		{
			name:                 "max int cooldown days does not overflow",
			publishDate:          now.Add(-1 * day),
			cooldownDays:         int(^uint(0) >> 1),
			wantWithinCooldown:   true,
			wantDaysSincePublish: 1,
			wantDaysRemaining:    int(^uint(0)>>1) - 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withinCooldown, daysSincePublish, daysRemaining := cooldownIsWithinWindow(tt.publishDate, tt.cooldownDays)
			assert.Equal(t, tt.wantWithinCooldown, withinCooldown, "withinCooldown")
			assert.Equal(t, tt.wantDaysSincePublish, daysSincePublish, "daysSincePublish")
			assert.Equal(t, tt.wantDaysRemaining, daysRemaining, "daysRemaining")
		})
	}
}

func TestCooldownOldestVersion(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour

	t.Run("returns version with earliest publish date", func(t *testing.T) {
		dates := map[string]time.Time{
			"1.0.0": now.Add(-30 * day),
			"2.0.0": now.Add(-10 * day),
			"3.0.0": now.Add(-1 * day),
		}
		ver, ts := cooldownOldestVersion(dates)
		assert.Equal(t, "1.0.0", ver)
		assert.False(t, ts.IsZero())
	})

	t.Run("single version", func(t *testing.T) {
		dates := map[string]time.Time{"1.0.0": now.Add(-5 * day)}
		ver, _ := cooldownOldestVersion(dates)
		assert.Equal(t, "1.0.0", ver)
	})

	t.Run("empty map returns empty string and zero time", func(t *testing.T) {
		ver, ts := cooldownOldestVersion(map[string]time.Time{})
		assert.Empty(t, ver)
		assert.True(t, ts.IsZero())
	})
}

func TestCooldownLatestEligibleVersion(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour

	t.Run("returns most recently published non-blocked version", func(t *testing.T) {
		dates := map[string]time.Time{
			"1.0.0": now.Add(-30 * day),
			"2.0.0": now.Add(-10 * day),
			"3.0.0": now.Add(-1 * day),
		}
		tooNew := map[string]bool{"3.0.0": true}
		ver := cooldownLatestEligibleVersion(dates, tooNew)
		assert.Equal(t, "2.0.0", ver)
	})

	t.Run("all versions blocked returns empty string", func(t *testing.T) {
		dates := map[string]time.Time{"1.0.0": now, "2.0.0": now.Add(-1 * day)}
		tooNew := map[string]bool{"1.0.0": true, "2.0.0": true}
		ver := cooldownLatestEligibleVersion(dates, tooNew)
		assert.Empty(t, ver)
	})

	t.Run("empty tooNew returns latest version", func(t *testing.T) {
		dates := map[string]time.Time{
			"1.0.0": now.Add(-30 * day),
			"2.0.0": now.Add(-10 * day),
		}
		ver := cooldownLatestEligibleVersion(dates, map[string]bool{})
		assert.Equal(t, "2.0.0", ver)
	})
}
