package ecoscan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

type nodePackageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ScanNodeModules reads a node_modules directory and returns every package
// found directly inside it (including @scope/name packages), recursing into
// nested node_modules directories for dependency nesting.
func ScanNodeModules(dir string) ([]FoundPackage, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var found []FoundPackage
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		if strings.HasPrefix(entry.Name(), "@") {
			scopeDir := filepath.Join(dir, entry.Name())
			scopedEntries, err := os.ReadDir(scopeDir)
			if err != nil {
				continue
			}
			for _, scoped := range scopedEntries {
				if scoped.IsDir() {
					found = append(found, scanNodePackageDir(filepath.Join(scopeDir, scoped.Name()))...)
				}
			}
			continue
		}

		found = append(found, scanNodePackageDir(filepath.Join(dir, entry.Name()))...)
	}
	return found, nil
}

// scanNodePackageDir reads a single package's package.json (if present) and
// recurses into any nested node_modules inside it.
func scanNodePackageDir(pkgDir string) []FoundPackage {
	var found []FoundPackage

	if data, err := os.ReadFile(filepath.Join(pkgDir, "package.json")); err == nil {
		var pj nodePackageJSON
		if err := json.Unmarshal(data, &pj); err == nil && pj.Name != "" && pj.Version != "" {
			found = append(found, FoundPackage{
				Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
				Name:      pj.Name,
				Version:   pj.Version,
				Path:      pkgDir,
			})
		}
	}

	nested := filepath.Join(pkgDir, "node_modules")
	if info, err := os.Stat(nested); err == nil && info.IsDir() {
		if nestedFound, err := ScanNodeModules(nested); err == nil {
			found = append(found, nestedFound...)
		}
	}

	return found
}
