// internal/ecoscan/types.go
package ecoscan

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

// FoundPackage is a single occurrence of an installed package discovered on disk.
type FoundPackage struct {
	Ecosystem packagev1.Ecosystem
	Name      string
	Version   string
	Path      string
}

// UniquePackage is a package collapsed across every path it was found at,
// keyed by (Ecosystem, Name, Version).
type UniquePackage struct {
	Ecosystem packagev1.Ecosystem
	Name      string
	Version   string
	Paths     []string
}

// EcosystemName returns the lowercase wire name used in the scan-report JSON
// payload and in removal-command hints.
func EcosystemName(e packagev1.Ecosystem) string {
	switch e {
	case packagev1.Ecosystem_ECOSYSTEM_NPM:
		return "npm"
	case packagev1.Ecosystem_ECOSYSTEM_PYPI:
		return "pypi"
	default:
		return "unknown"
	}
}
