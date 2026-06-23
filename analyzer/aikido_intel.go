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
	"sync/atomic"
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
	mu         sync.Mutex
	once       sync.Once
	snapshot   *aikidoSnapshot
	refreshing atomic.Bool // true while a background refresh goroutine is running
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
		// No feed and no usable disk cache: we genuinely could not check.
		// Mark degraded so the composite can fail closed under paranoid mode.
		allow.Degraded = true
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
	snap := eco.snapshot
	fresh := snap != nil && time.Since(snap.fetchedAt) < a.cfg.CacheTTL
	eco.mu.Unlock()

	if fresh {
		return snap
	}

	// No data yet — block on first load to guarantee correctness.
	if snap == nil {
		eco.once.Do(func() {
			loaded := a.loadSnapshot(ctx, feedPath, ecoName)
			if loaded != nil {
				eco.mu.Lock()
				eco.snapshot = loaded
				eco.mu.Unlock()
			}
		})
		eco.mu.Lock()
		s := eco.snapshot
		eco.mu.Unlock()
		return s
	}

	// Stale data exists — serve it immediately and refresh in background so
	// the caller is never blocked waiting for the network.
	if eco.refreshing.CompareAndSwap(false, true) {
		go func() {
			defer eco.refreshing.Store(false)
			loaded := a.loadSnapshot(context.Background(), feedPath, ecoName)
			if loaded != nil {
				eco.mu.Lock()
				eco.snapshot = loaded
				eco.mu.Unlock()
			}
		}()
	}
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

// Refresh forces an immediate re-fetch of both ecosystem feeds, bypassing the TTL.
// It is safe to call concurrently; only the first caller per ecosystem fetches — the rest wait.
// Returns an error only when every feed fails. Partial failures are logged.
func (a *aikidoIntelAnalyzer) Refresh(ctx context.Context) error {
	type ecoSpec struct {
		eco      *aikidoEcosystem
		feedPath string
		ecoName  string
	}
	specs := []ecoSpec{
		{a.npm, "/malware_predictions.json", "npm"},
		{a.pypi, "/malware_pypi.json", "pypi"},
	}

	var failures int
	for _, s := range specs {
		loaded := a.loadSnapshot(ctx, s.feedPath, s.ecoName)
		if loaded == nil {
			failures++
			continue
		}
		s.eco.mu.Lock()
		s.eco.snapshot = loaded
		s.eco.mu.Unlock()
		// Mark once as done so getSnapshot's blocking path is never re-entered.
		s.eco.once.Do(func() {})
	}

	if failures == len(specs) {
		return fmt.Errorf("aikido-intel: all feed refreshes failed")
	}
	return nil
}

func (a *aikidoIntelAnalyzer) diskCachePath(ecoName string) string {
	return filepath.Join(a.cfg.CacheDir, fmt.Sprintf("aikido-%s.json", ecoName))
}

func (a *aikidoIntelAnalyzer) writeDiskCache(ecoName string, entries []aikidoEntry) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(a.cfg.CacheDir, 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
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
