package cloud

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestServer creates an httptest server on IPv6 loopback [::1] because
// WSL2 blocks IPv4 127.0.0.1 TCP loopback. Falls back to httptest.NewServer
// if IPv6 is unavailable.
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

func TestVerifySHA256_Match(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "bin")
	require.NoError(t, err)
	_, _ = f.Write([]byte("hello"))
	f.Close()
	h := sha256.Sum256([]byte("hello"))
	require.NoError(t, verifySHA256(f.Name(), fmt.Sprintf("%x", h[:])))
}

func TestVerifySHA256_Mismatch(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "bin")
	require.NoError(t, err)
	_, _ = f.Write([]byte("hello"))
	f.Close()
	err = verifySHA256(f.Name(), "wronghash")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sha256 mismatch")
}

func TestDownloadBinary_Success(t *testing.T) {
	content := []byte("fake binary content")
	srv := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "testkey", r.Header.Get("Authorization"))
		w.Write(content)
	}))
	defer srv.Close()
	dst := filepath.Join(t.TempDir(), "pmg.download")
	require.NoError(t, downloadBinary(t.Context(), "testkey", srv.URL+"/download/pmg", dst))
	got, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, content, got)
}

func TestDownloadBinary_ServerError(t *testing.T) {
	srv := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	dst := filepath.Join(t.TempDir(), "pmg.download")
	err := downloadBinary(t.Context(), "key", srv.URL+"/download/pmg", dst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}
