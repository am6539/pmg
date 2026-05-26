package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	semver "github.com/Masterminds/semver/v3"
	"github.com/safedep/dry/log"
)

type AikidoIntelAnalyzerConfig struct {
	BaseURL     string
	CacheDir    string
	CacheTTL    time.Duration
	HTTPTimeout time.Duration
}

type aikidoEntry struct {
	PackageName string `json:"package_name"`
	Version     string `json:"version"`
	Reason      string `json:"reason"`
}

type aikidoRangeEntry struct {
	entry      aikidoEntry
	constraint *semver.Constraints
}

type aikidoSnapshot struct {
	exact     map[string]aikidoEntry        // key: "name:version" — O(1) exact lookup
	ranges    map[string][]aikidoRangeEntry // key: package name — semver range / wildcard entries
	fetchedAt time.Time
}

type aikidoEcosystem struct {
	mu       sync.Mutex
	once     sync.Once
	snapshot *aikidoSnapshot
}

type aikidoIntelAnalyzer struct {
	cfg  AikidoIntelAnalyzerConfig
	npm  *aikidoEcosystem
	pypi *aikidoEcosystem
}

var _ Analyzer = &aikidoIntelAnalyzer{}
var _ PackageVersionAnalyzer = &aikidoIntelAnalyzer{}

func NewAikidoIntelAnalyzer(cfg AikidoIntelAnalyzerConfig) (*aikidoIntelAnalyzer, error) {
	return &aikidoIntelAnalyzer{
		cfg:  cfg,
		npm:  &aikidoEcosystem{},
		pypi: &aikidoEcosystem{},
	}, nil
}

func (a *aikidoIntelAnalyzer) Name() string {
	return "aikido-intel"
}

func (a *aikidoIntelAnalyzer) Analyze(ctx context.Context, pv *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error) {
	allow := &PackageVersionAnalysisResult{
		PackageVersion: pv,
		Action:         ActionAllow,
	}

	eco, feedPath, ecoName := a.resolveEcosystem(pv)
	if eco == nil {
		return allow, nil
	}

	snap := a.getSnapshot(ctx, eco, feedPath, ecoName)
	if snap == nil {
		return allow, nil
	}

	key := pv.GetPackage().GetName() + ":" + pv.GetVersion()
	if entry, ok := snap.exact[key]; ok {
		return aikidoBlockResult(pv, entry, ecoName), nil
	}

	// Check semver range / wildcard entries for this package name.
	if rangeEntries, ok := snap.ranges[pv.GetPackage().GetName()]; ok {
		sv, err := semver.NewVersion(pv.GetVersion())
		if err == nil {
			for _, re := range rangeEntries {
				if re.constraint.Check(sv) {
					return aikidoBlockResult(pv, re.entry, ecoName), nil
				}
			}
		}
	}

	return allow, nil
}

func (a *aikidoIntelAnalyzer) resolveEcosystem(pv *packagev1.PackageVersion) (*aikidoEcosystem, string, string) {
	switch pv.GetPackage().GetEcosystem() {
	case packagev1.Ecosystem_ECOSYSTEM_NPM:
		return a.npm, "/malware_predictions.json", "npm"
	case packagev1.Ecosystem_ECOSYSTEM_PYPI:
		return a.pypi, "/malware_pypi.json", "pypi"
	default:
		return nil, "", ""
	}
}

func (a *aikidoIntelAnalyzer) getSnapshot(ctx context.Context, eco *aikidoEcosystem, feedPath, ecoName string) *aikidoSnapshot {
	eco.mu.Lock()
	if eco.snapshot != nil && time.Since(eco.snapshot.fetchedAt) < a.cfg.CacheTTL {
		snap := eco.snapshot
		eco.mu.Unlock()
		return snap
	}
	eco.mu.Unlock()

	// sync.Once prevents concurrent fetch storms on first load.
	// After TTL expiry we fall through to return the stale snapshot.
	eco.once.Do(func() {
		snap := a.loadSnapshot(ctx, feedPath, ecoName)
		if snap != nil {
			eco.mu.Lock()
			eco.snapshot = snap
			eco.mu.Unlock()
		}
	})

	eco.mu.Lock()
	snap := eco.snapshot
	eco.mu.Unlock()
	return snap
}

func (a *aikidoIntelAnalyzer) loadSnapshot(ctx context.Context, feedPath, ecoName string) *aikidoSnapshot {
	entries, err := a.fetchFeed(ctx, feedPath)
	if err != nil {
		log.Warnf("aikido-intel: failed to fetch feed %s: %v", feedPath, err)
		entries, err = a.readDiskCache(ecoName)
		if err != nil {
			log.Warnf("aikido-intel: no disk cache for %s: %v", ecoName, err)
			return nil
		}
	} else {
		if writeErr := a.writeDiskCache(ecoName, entries); writeErr != nil {
			log.Warnf("aikido-intel: failed to write disk cache for %s: %v", ecoName, writeErr)
		}
	}

	exact := make(map[string]aikidoEntry, len(entries))
	ranges := make(map[string][]aikidoRangeEntry)

	for _, e := range entries {
		if isExactAikidoVersion(e.Version) {
			exact[e.PackageName+":"+e.Version] = e
			continue
		}
		c, err := semver.NewConstraint(e.Version)
		if err != nil {
			log.Warnf("aikido-intel: skipping unparseable version range %q for %s: %v", e.Version, e.PackageName, err)
			continue
		}
		ranges[e.PackageName] = append(ranges[e.PackageName], aikidoRangeEntry{entry: e, constraint: c})
	}

	return &aikidoSnapshot{exact: exact, ranges: ranges, fetchedAt: time.Now()}
}

func (a *aikidoIntelAnalyzer) fetchFeed(ctx context.Context, feedPath string) ([]aikidoEntry, error) {
	httpClient := &http.Client{Timeout: a.cfg.HTTPTimeout}
	url := a.cfg.BaseURL + feedPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	var entries []aikidoEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}

	return entries, nil
}

func (a *aikidoIntelAnalyzer) diskCachePath(ecoName string) string {
	return filepath.Join(a.cfg.CacheDir, fmt.Sprintf("aikido-%s.json", ecoName))
}

func (a *aikidoIntelAnalyzer) writeDiskCache(ecoName string, entries []aikidoEntry) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	return os.WriteFile(a.diskCachePath(ecoName), data, 0o600)
}

func (a *aikidoIntelAnalyzer) readDiskCache(ecoName string) ([]aikidoEntry, error) {
	data, err := os.ReadFile(a.diskCachePath(ecoName))
	if err != nil {
		return nil, err
	}
	var entries []aikidoEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// isExactAikidoVersion returns true when v is a plain version string with no range operators.
// Strings containing >, <, =, ^, ~, *, |, or whitespace are treated as semver constraints.
func isExactAikidoVersion(v string) bool {
	return !strings.ContainsAny(v, "><^~*| \t") && !strings.Contains(v, "=")
}

func aikidoBlockResult(pv *packagev1.PackageVersion, entry aikidoEntry, ecoName string) *PackageVersionAnalysisResult {
	return &PackageVersionAnalysisResult{
		PackageVersion: pv,
		Action:         ActionBlock,
		IsMalware:      true,
		IsVerified:     true,
		Summary:        entry.Reason,
		AnalysisID:     fmt.Sprintf("aikido:%s:%s@%s", ecoName, pv.GetPackage().GetName(), pv.GetVersion()),
		ReferenceURL:   fmt.Sprintf("https://aikido.dev/malware/%s/%s", pv.GetPackage().GetName(), pv.GetVersion()),
	}
}
