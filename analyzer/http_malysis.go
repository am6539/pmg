package analyzer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	"github.com/safedep/pmg/config"
	"google.golang.org/protobuf/proto"
)

// httpMalysisAnalyzer implements PackageVersionAnalyzer over HTTP POST.
// It sends QueryPackageAnalysisRequest as protobuf to the pmg-cloud HTTP endpoint
// and returns the result, applying the same IsMalware/IsVerified logic as malysisQueryAnalyzer.
type httpMalysisAnalyzer struct {
	url    string // e.g. "https://host/api/malysis"
	apiKey string
	client *http.Client
}

var _ Analyzer = &httpMalysisAnalyzer{}
var _ PackageVersionAnalyzer = &httpMalysisAnalyzer{}

// NewHTTPMalysisAnalyzer creates an analyzer that queries pmg-cloud's /api/malysis endpoint.
func NewHTTPMalysisAnalyzer(url, apiKey string) *httpMalysisAnalyzer {
	return &httpMalysisAnalyzer{
		url:    url,
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *httpMalysisAnalyzer) Name() string {
	return "http-malysis"
}

func (a *httpMalysisAnalyzer) Analyze(ctx context.Context,
	packageVersion *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error) {

	reqPb := &malysisv1.QueryPackageAnalysisRequest{
		Target: &malysisv1pb.PackageAnalysisTarget{
			PackageVersion: packageVersion,
		},
	}

	body, err := proto.Marshal(reqPb)
	if err != nil {
		return nil, fmt.Errorf("http-malysis: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("http-malysis: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	if a.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http-malysis: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("http-malysis: unauthorized — check API key")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http-malysis: server returned %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("http-malysis: read response: %w", err)
	}

	var res malysisv1.QueryPackageAnalysisResponse
	if err := proto.Unmarshal(respBody, &res); err != nil {
		return nil, fmt.Errorf("http-malysis: parse response: %w", err)
	}

	analysisResult := &PackageVersionAnalysisResult{
		PackageVersion: packageVersion,
		ReferenceURL:   malysisReportUrl(res.GetAnalysisId()),
		Action:         ActionAllow,
		AnalysisID:     res.GetAnalysisId(),
		Summary:        res.GetReport().GetInference().GetSummary(),
		Data:           res.GetReport(),
	}

	cfg := config.Get()
	if res.GetReport().GetInference().GetIsMalware() {
		analysisResult.IsMalware = true
		analysisResult.Action = ActionConfirm

		if cfg.Config.Paranoid {
			analysisResult.Action = ActionBlock
		}
	}

	if res.GetVerificationRecord().GetIsMalware() {
		analysisResult.IsMalware = true
		analysisResult.IsVerified = true
		analysisResult.Action = ActionBlock
	}

	return analysisResult, nil
}

// chainMalysisAnalyzer tries the primary analyzer first; on first error it permanently
// falls back to the secondary analyzer for the session.
type chainMalysisAnalyzer struct {
	primary     PackageVersionAnalyzer
	fallback    PackageVersionAnalyzer
	useFallback bool
	mu          sync.Mutex
}

// NewChainMalysisAnalyzer returns a PackageVersionAnalyzer that tries primary first,
// then permanently falls back to fallback on the first error.
func NewChainMalysisAnalyzer(primary, fallback PackageVersionAnalyzer) PackageVersionAnalyzer {
	return &chainMalysisAnalyzer{primary: primary, fallback: fallback}
}

func (c *chainMalysisAnalyzer) Name() string {
	return c.primary.Name() + "+fallback:" + c.fallback.Name()
}

func (c *chainMalysisAnalyzer) Analyze(ctx context.Context,
	packageVersion *packagev1.PackageVersion) (*PackageVersionAnalysisResult, error) {

	c.mu.Lock()
	useFallback := c.useFallback
	c.mu.Unlock()

	if useFallback {
		return c.fallback.Analyze(ctx, packageVersion)
	}

	result, err := c.primary.Analyze(ctx, packageVersion)
	if err == nil {
		return result, nil
	}

	c.mu.Lock()
	c.useFallback = true
	c.mu.Unlock()

	return c.fallback.Analyze(ctx, packageVersion)
}
