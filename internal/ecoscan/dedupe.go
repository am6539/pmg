// internal/ecoscan/dedupe.go
package ecoscan

import "fmt"

// Dedupe collapses found occurrences into one UniquePackage per distinct
// (Ecosystem, Name, Version), preserving first-seen order and merging Paths.
func Dedupe(found []FoundPackage) []UniquePackage {
	index := make(map[string]int, len(found))
	var unique []UniquePackage

	for _, f := range found {
		key := fmt.Sprintf("%d:%s:%s", f.Ecosystem, f.Name, f.Version)
		if i, ok := index[key]; ok {
			unique[i].Paths = append(unique[i].Paths, f.Path)
			continue
		}
		index[key] = len(unique)
		unique = append(unique, UniquePackage{
			Ecosystem: f.Ecosystem,
			Name:      f.Name,
			Version:   f.Version,
			Paths:     []string{f.Path},
		})
	}
	return unique
}
