package policy

import (
	"encoding/json"
	"os"
	"strings"
)

// Decision is the org-policy verdict for a package version.
type Decision int

const (
	DecisionNone  Decision = iota // no matching rule
	DecisionAllow                 // explicitly allowed (overrides block)
	DecisionBlock                 // explicitly blocked
)

// Rule mirrors the pmg-cloud PolicyRule shape (only the fields the agent needs).
type Rule struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Reason    string `json:"reason,omitempty"`
}

// Policy is the cached org policy pushed from pmg-cloud.
type Policy struct {
	Blocklist []Rule `json:"blocklist"`
	Allowlist []Rule `json:"allowlist"`
}

// Decision returns the policy verdict. Allowlist takes precedence over Blocklist.
func (p *Policy) Decision(ecosystem, name, version string) Decision {
	if matches(p.Allowlist, ecosystem, name, version) {
		return DecisionAllow
	}
	if matches(p.Blocklist, ecosystem, name, version) {
		return DecisionBlock
	}
	return DecisionNone
}

func matches(rules []Rule, ecosystem, name, version string) bool {
	for _, r := range rules {
		if !strings.EqualFold(r.Name, name) {
			continue
		}
		if r.Ecosystem != "" && !strings.EqualFold(r.Ecosystem, ecosystem) {
			continue
		}
		if r.Version == "*" || r.Version == "" || r.Version == version {
			return true
		}
	}
	return false
}

// Save writes the policy to path as JSON.
func Save(path string, p *Policy) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Load reads a cached policy; a missing file yields an empty policy (no error).
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Policy{}, nil
	}
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
