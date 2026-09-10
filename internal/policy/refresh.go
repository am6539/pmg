package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/safedep/dry/log"
)

// refreshTimeout bounds the live policy fetch so a slow/unreachable
// pmg-cloud server never stalls package installation for long.
const refreshTimeout = 2 * time.Second

// RefreshFromCloud fetches the current org policy from pmg-cloud and
// overwrites the local cache at cachePath. It is best-effort: any failure
// (no API key, unreachable server, bad response) is logged and ignored,
// leaving the existing cache in place so callers can proceed with
// whatever policy was last fetched via heartbeat.
func RefreshFromCloud(baseURL, apiKey, cachePath string) {
	if apiKey == "" {
		return
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" || strings.Contains(baseURL, "aikido.dev") {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/policy", nil)
	if err != nil {
		log.Debugf("policy: refresh: build request: %v", err)
		return
	}
	req.Header.Set("Authorization", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Debugf("policy: refresh: request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Debugf("policy: refresh: unexpected status %d", resp.StatusCode)
		return
	}

	var body struct {
		Policy *Policy `json:"policy"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		log.Debugf("policy: refresh: decode response: %v", err)
		return
	}
	if body.Policy == nil {
		log.Debugf("policy: refresh: response had no policy")
		return
	}

	if err := Save(cachePath, body.Policy); err != nil {
		log.Debugf("policy: refresh: save cache: %v", err)
	}
}
