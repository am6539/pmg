package audit

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	servicev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/safedep/dry/cloud/endpointsync"
	"github.com/safedep/dry/log"
	"google.golang.org/protobuf/proto"
)

// httpEventTransport implements endpointsync.EventTransport over HTTP/1.1 POST.
// Use as fallback when gRPC (HTTP/2) is unavailable, e.g. behind Cloudflare Tunnel.
type httpEventTransport struct {
	url    string
	apiKey string
	client *http.Client
}

func newHTTPEventTransport(url, apiKey string) endpointsync.EventTransport {
	return &httpEventTransport{
		url:    url,
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (t *httpEventTransport) Send(ctx context.Context, req *servicev1.SyncEventsRequest) (*servicev1.SyncEventsResponse, error) {
	body, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("http transport: marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("http transport: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	if t.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+t.apiKey)
	}

	resp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http transport: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("http transport: unauthorized — check API key")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http transport: server returned %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("http transport: read response: %w", err)
	}

	var syncResp servicev1.SyncEventsResponse
	if err := proto.Unmarshal(respBody, &syncResp); err != nil {
		return nil, fmt.Errorf("http transport: parse response: %w", err)
	}
	return &syncResp, nil
}

func (t *httpEventTransport) Close() error { return nil }

// chainEventTransport tries the primary (gRPC) transport first; on first failure,
// permanently falls back to the secondary (HTTP) transport for the session.
type chainEventTransport struct {
	primary     endpointsync.EventTransport
	fallback    endpointsync.EventTransport
	useFallback bool
	mu          sync.Mutex
}

func newChainEventTransport(primary, fallback endpointsync.EventTransport) endpointsync.EventTransport {
	return &chainEventTransport{primary: primary, fallback: fallback}
}

func (c *chainEventTransport) Send(ctx context.Context, req *servicev1.SyncEventsRequest) (*servicev1.SyncEventsResponse, error) {
	c.mu.Lock()
	useFallback := c.useFallback
	c.mu.Unlock()

	if useFallback {
		return c.fallback.Send(ctx, req)
	}

	resp, err := c.primary.Send(ctx, req)
	if err == nil {
		return resp, nil
	}

	log.Debugf("gRPC transport failed, switching to HTTP fallback: %v", err)
	c.mu.Lock()
	c.useFallback = true
	c.mu.Unlock()

	return c.fallback.Send(ctx, req)
}

func (c *chainEventTransport) Close() error {
	var firstErr error
	if err := c.primary.Close(); err != nil {
		firstErr = err
	}
	if err := c.fallback.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// cloudHTTPSyncURL derives the /api/sync URL from the gRPC address.
// addr is "host:port" (e.g. "package.thanhvpga.qzz.io:443" or "localhost:8080").
func cloudHTTPSyncURL(addr string, insecure bool) string {
	scheme := "https"
	if insecure {
		scheme = "http"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return scheme + "://" + addr + "/api/sync"
	}
	if (!insecure && port == "443") || (insecure && port == "80") {
		return scheme + "://" + host + "/api/sync"
	}
	return scheme + "://" + host + ":" + port + "/api/sync"
}
