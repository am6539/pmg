package analyzer

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestServer creates an httptest server on IPv6 loopback [::1] because
// WSL2 (Windows Subsystem for Linux) blocks IPv4 127.0.0.1 TCP loopback.
// Falls back to httptest.NewServer if IPv6 is unavailable.
func newTestServer(handler http.Handler) *httptest.Server {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return httptest.NewServer(handler)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = l
	srv.Start()
	return srv
}

// feedEntry mirrors the Aikido feed JSON schema: [{package_name, version, reason}]
type feedEntry struct {
	PackageName string `json:"package_name"`
	Version     string `json:"version"`
	Reason      string `json:"reason"`
}

func serveFeed(t *testing.T, npmEntries, pypiEntries []feedEntry) (srv *httptest.Server, requestCount *atomic.Int64) {
	t.Helper()
	count := &atomic.Int64{}
	srv = newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		var entries []feedEntry
		switch r.URL.Path {
		case "/malware_predictions.json":
			entries = npmEntries
		case "/malware_pypi.json":
			entries = pypiEntries
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	}))
	t.Cleanup(srv.Close)
	return srv, count
}

func makeAikidoAnalyzer(t *testing.T, baseURL string) *aikidoIntelAnalyzer {
	t.Helper()
	an, err := NewAikidoIntelAnalyzer(AikidoIntelAnalyzerConfig{
		BaseURL:     baseURL,
		CacheDir:    t.TempDir(),
		CacheTTL:    1 * time.Hour,
		HTTPTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	return an
}

func npmPkg(name, version string) *packagev1.PackageVersion {
	return &packagev1.PackageVersion{
		Package: &packagev1.Package{
			Name:      name,
			Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
		},
		Version: version,
	}
}

func pypiPkg(name, version string) *packagev1.PackageVersion {
	return &packagev1.PackageVersion{
		Package: &packagev1.Package{
			Name:      name,
			Ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI,
		},
		Version: version,
	}
}

func mavenPkg(name, version string) *packagev1.PackageVersion {
	return &packagev1.PackageVersion{
		Package: &packagev1.Package{
			Name:      name,
			Ecosystem: packagev1.Ecosystem_ECOSYSTEM_MAVEN,
		},
		Version: version,
	}
}

func TestAikidoIntel_Name(t *testing.T) {
	srv, _ := serveFeed(t, nil, nil)
	an := makeAikidoAnalyzer(t, srv.URL)
	assert.Equal(t, "aikido-intel", an.Name())
}

func TestAikidoIntel_MissOnUnknownNpmPackage(t *testing.T) {
	srv, _ := serveFeed(t, []feedEntry{
		{PackageName: "evil-pkg", Version: "1.0.0", Reason: "MALWARE"},
	}, nil)
	an := makeAikidoAnalyzer(t, srv.URL)

	result, err := an.Analyze(context.Background(), npmPkg("safe-pkg", "1.0.0"))
	require.NoError(t, err)
	assert.Equal(t, ActionAllow, result.Action)
	assert.False(t, result.IsMalware)
}

func TestAikidoIntel_BlockOnKnownMaliciousNpmPackage(t *testing.T) {
	srv, _ := serveFeed(t, []feedEntry{
		{PackageName: "evil-pkg", Version: "1.0.0", Reason: "MALWARE"},
	}, nil)
	an := makeAikidoAnalyzer(t, srv.URL)

	result, err := an.Analyze(context.Background(), npmPkg("evil-pkg", "1.0.0"))
	require.NoError(t, err)
	assert.Equal(t, ActionBlock, result.Action)
	assert.True(t, result.IsMalware)
	assert.True(t, result.IsVerified)
	assert.NotEmpty(t, result.Summary)
	assert.NotEmpty(t, result.AnalysisID)
	assert.NotEmpty(t, result.ReferenceURL)
}

func TestAikidoIntel_BlockOnKnownMaliciousPypiPackage(t *testing.T) {
	srv, _ := serveFeed(t, nil, []feedEntry{
		{PackageName: "bad-lib", Version: "2.3.4", Reason: "MALWARE"},
	})
	an := makeAikidoAnalyzer(t, srv.URL)

	result, err := an.Analyze(context.Background(), pypiPkg("bad-lib", "2.3.4"))
	require.NoError(t, err)
	assert.Equal(t, ActionBlock, result.Action)
	assert.True(t, result.IsMalware)
	assert.True(t, result.IsVerified)
}

func TestAikidoIntel_VersionMismatchAllows(t *testing.T) {
	srv, _ := serveFeed(t, []feedEntry{
		{PackageName: "evil-pkg", Version: "1.0.0", Reason: "MALWARE"},
	}, nil)
	an := makeAikidoAnalyzer(t, srv.URL)

	result, err := an.Analyze(context.Background(), npmPkg("evil-pkg", "2.0.0"))
	require.NoError(t, err)
	assert.Equal(t, ActionAllow, result.Action)
}

func TestAikidoIntel_UnsupportedEcosystemAllows(t *testing.T) {
	srv, requestCount := serveFeed(t, nil, nil)
	an := makeAikidoAnalyzer(t, srv.URL)

	result, err := an.Analyze(context.Background(), mavenPkg("com.example:lib", "1.0.0"))
	require.NoError(t, err)
	assert.Equal(t, ActionAllow, result.Action)
	assert.Equal(t, int64(0), requestCount.Load())
}

func TestAikidoIntel_CacheHitDoesNotRefetch(t *testing.T) {
	srv, requestCount := serveFeed(t, []feedEntry{
		{PackageName: "evil-pkg", Version: "1.0.0", Reason: "MALWARE"},
	}, nil)
	an := makeAikidoAnalyzer(t, srv.URL)

	_, err := an.Analyze(context.Background(), npmPkg("evil-pkg", "1.0.0"))
	require.NoError(t, err)

	_, err = an.Analyze(context.Background(), npmPkg("safe-pkg", "1.0.0"))
	require.NoError(t, err)

	assert.Equal(t, int64(1), requestCount.Load())
}

func TestAikidoIntel_NetworkFailureWithNoCacheAllows(t *testing.T) {
	srv := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	an := makeAikidoAnalyzer(t, srv.URL)

	result, err := an.Analyze(context.Background(), npmPkg("any-pkg", "1.0.0"))
	require.NoError(t, err)
	assert.Equal(t, ActionAllow, result.Action)
}

func TestAikidoIntel_NetworkFailureWithDiskCacheUsesCache(t *testing.T) {
	cacheDir := t.TempDir()

	srv, _ := serveFeed(t, []feedEntry{
		{PackageName: "cached-evil", Version: "1.0.0", Reason: "MALWARE"},
	}, nil)
	an1, err := NewAikidoIntelAnalyzer(AikidoIntelAnalyzerConfig{
		BaseURL:     srv.URL,
		CacheDir:    cacheDir,
		CacheTTL:    1 * time.Millisecond,
		HTTPTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	_, err = an1.Analyze(context.Background(), npmPkg("cached-evil", "1.0.0"))
	require.NoError(t, err)
	srv.Close()

	an2, err := NewAikidoIntelAnalyzer(AikidoIntelAnalyzerConfig{
		BaseURL:     "http://127.0.0.1:0",
		CacheDir:    cacheDir,
		CacheTTL:    1 * time.Millisecond,
		HTTPTimeout: 200 * time.Millisecond,
	})
	require.NoError(t, err)

	result, err := an2.Analyze(context.Background(), npmPkg("cached-evil", "1.0.0"))
	require.NoError(t, err)
	assert.Equal(t, ActionBlock, result.Action)
}

func TestAikidoIntel_MalformedJSONAllows(t *testing.T) {
	srv := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not valid json {{{"))
	}))
	defer srv.Close()

	an := makeAikidoAnalyzer(t, srv.URL)

	result, err := an.Analyze(context.Background(), npmPkg("any-pkg", "1.0.0"))
	require.NoError(t, err)
	assert.Equal(t, ActionAllow, result.Action)
}

func TestAikidoIntel_ConcurrentAnalyzeTriggersOneFetch(t *testing.T) {
	var requestCount atomic.Int64
	srv := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		time.Sleep(20 * time.Millisecond)
		json.NewEncoder(w).Encode([]feedEntry{
			{PackageName: "evil-pkg", Version: "1.0.0", Reason: "MALWARE"},
		})
	}))
	defer srv.Close()

	an := makeAikidoAnalyzer(t, srv.URL)

	const goroutines = 20
	done := make(chan struct{}, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			an.Analyze(context.Background(), npmPkg("evil-pkg", "1.0.0")) //nolint:errcheck
			done <- struct{}{}
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}

	assert.Equal(t, int64(1), requestCount.Load())
}

func TestAikidoIntel_AnalysisIDFormat(t *testing.T) {
	srv, _ := serveFeed(t, []feedEntry{
		{PackageName: "evil-pkg", Version: "3.2.1", Reason: "MALWARE"},
	}, nil)
	an := makeAikidoAnalyzer(t, srv.URL)

	result, err := an.Analyze(context.Background(), npmPkg("evil-pkg", "3.2.1"))
	require.NoError(t, err)
	assert.Equal(t, "aikido:npm:evil-pkg@3.2.1", result.AnalysisID)
	assert.Contains(t, result.ReferenceURL, "evil-pkg")
}

func TestAikidoIntel_WildcardVersionBlocks(t *testing.T) {
	srv, _ := serveFeed(t, []feedEntry{
		{PackageName: "evil-pkg", Version: "*", Reason: "MALWARE"},
	}, nil)
	an := makeAikidoAnalyzer(t, srv.URL)

	result, err := an.Analyze(context.Background(), npmPkg("evil-pkg", "9.9.9"))
	require.NoError(t, err)
	assert.Equal(t, ActionBlock, result.Action)
	assert.True(t, result.IsMalware)
}

func TestAikidoIntel_SemverRangeBlocks(t *testing.T) {
	srv, _ := serveFeed(t, []feedEntry{
		{PackageName: "evil-pkg", Version: ">=1.0.0 <3.0.0", Reason: "MALWARE"},
	}, nil)
	an := makeAikidoAnalyzer(t, srv.URL)

	result, err := an.Analyze(context.Background(), npmPkg("evil-pkg", "2.5.0"))
	require.NoError(t, err)
	assert.Equal(t, ActionBlock, result.Action)
}

func TestAikidoIntel_SemverRangeDoesNotMatchOutside(t *testing.T) {
	srv, _ := serveFeed(t, []feedEntry{
		{PackageName: "evil-pkg", Version: ">=1.0.0 <2.0.0", Reason: "MALWARE"},
	}, nil)
	an := makeAikidoAnalyzer(t, srv.URL)

	result, err := an.Analyze(context.Background(), npmPkg("evil-pkg", "3.0.0"))
	require.NoError(t, err)
	assert.Equal(t, ActionAllow, result.Action)
}

func TestAikidoIntel_DiskCacheWrittenAfterFetch(t *testing.T) {
	cacheDir := t.TempDir()
	srv, _ := serveFeed(t, []feedEntry{
		{PackageName: "pkg", Version: "1.0.0", Reason: "MALWARE"},
	}, nil)
	an, err := NewAikidoIntelAnalyzer(AikidoIntelAnalyzerConfig{
		BaseURL:     srv.URL,
		CacheDir:    cacheDir,
		CacheTTL:    1 * time.Hour,
		HTTPTimeout: 5 * time.Second,
	})
	require.NoError(t, err)

	_, err = an.Analyze(context.Background(), npmPkg("pkg", "1.0.0"))
	require.NoError(t, err)

	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	assert.NotEmpty(t, entries)
}
