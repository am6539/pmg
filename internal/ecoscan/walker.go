package ecoscan

import (
	"io/fs"
	"path/filepath"
	"strings"
)

// WalkResult is everything a single scan pass over a set of roots produced.
type WalkResult struct {
	Found       []FoundPackage
	SkippedDirs int
}

// Walk traverses every root, applying the Node and Python detectors, and
// pruning any directory for which shouldSkip returns true. Permission errors
// and other per-directory failures are counted in SkippedDirs rather than
// aborting the whole walk.
func Walk(roots []string, shouldSkip func(path string) bool) WalkResult {
	result := WalkResult{}

	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				result.SkippedDirs++
				return nil
			}
			if !d.IsDir() {
				return nil
			}
			if path != root && shouldSkip(path) {
				return filepath.SkipDir
			}

			base := d.Name()

			if base == "node_modules" {
				if found, err := ScanNodeModules(path); err == nil {
					result.Found = append(result.Found, found...)
				}
				return filepath.SkipDir
			}

			if strings.HasSuffix(base, ".dist-info") || strings.HasSuffix(base, ".egg-info") {
				if pkg, ok, err := DetectPythonPackage(path); err == nil && ok {
					result.Found = append(result.Found, pkg)
				}
				return filepath.SkipDir
			}

			return nil
		})
	}

	return result
}
