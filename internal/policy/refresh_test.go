package policy

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestServer creates an httptest server on IPv6 loopback [::1] because
// WSL2 (Windows Subsystem for Linux) blocks IPv4 127.0.0.1 TCP loopback.
// Falls back to httptest.NewServer if IPv6 is unavailable.
func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)
		return srv
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func TestRefreshFromCloud_SuccessOverwritesCache(t *testing.T) {
	server := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-key", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"policy": Policy{Blocklist: []Rule{{Ecosystem: "npm", Name: "evil", Version: "*"}}},
		})
	}))

	cachePath := filepath.Join(t.TempDir(), "cloud-policy.json")
	require.NoError(t, Save(cachePath, &Policy{}))

	RefreshFromCloud(server.URL, "test-key", cachePath)

	out, err := Load(cachePath)
	require.NoError(t, err)
	require.Len(t, out.Blocklist, 1)
	assert.Equal(t, "evil", out.Blocklist[0].Name)
}

func TestRefreshFromCloud_ServerErrorKeepsOldCache(t *testing.T) {
	server := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	cachePath := filepath.Join(t.TempDir(), "cloud-policy.json")
	original := &Policy{Blocklist: []Rule{{Ecosystem: "npm", Name: "keep-me", Version: "1.0.0"}}}
	require.NoError(t, Save(cachePath, original))

	RefreshFromCloud(server.URL, "test-key", cachePath)

	out, err := Load(cachePath)
	require.NoError(t, err)
	require.Len(t, out.Blocklist, 1)
	assert.Equal(t, "keep-me", out.Blocklist[0].Name)
}

func TestRefreshFromCloud_MalformedJSONKeepsOldCache(t *testing.T) {
	server := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))

	cachePath := filepath.Join(t.TempDir(), "cloud-policy.json")
	original := &Policy{Blocklist: []Rule{{Ecosystem: "npm", Name: "keep-me", Version: "1.0.0"}}}
	require.NoError(t, Save(cachePath, original))

	RefreshFromCloud(server.URL, "test-key", cachePath)

	out, err := Load(cachePath)
	require.NoError(t, err)
	require.Len(t, out.Blocklist, 1)
	assert.Equal(t, "keep-me", out.Blocklist[0].Name)
}

func TestRefreshFromCloud_EmptyAPIKeySkipsRequest(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
	}))
	defer server.Close()

	RefreshFromCloud(server.URL, "", filepath.Join(t.TempDir(), "cloud-policy.json"))

	assert.Equal(t, int32(0), atomic.LoadInt32(&requests))
}

func TestRefreshFromCloud_AikidoBaseURLSkipsRequest(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
	}))
	defer server.Close()

	RefreshFromCloud("https://intel.aikido.dev", "test-key", filepath.Join(t.TempDir(), "cloud-policy.json"))

	assert.Equal(t, int32(0), atomic.LoadInt32(&requests))
}
