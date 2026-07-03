package ecoscan

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

// ParsePackageMetadata reads the "Name:" and "Version:" fields from a Python
// package metadata file (PEP 566 "METADATA" for wheels, "PKG-INFO" for
// egg-info sdists — both use the same RFC822-style header format).
func ParsePackageMetadata(metadataPath string) (name, version string, err error) {
	f, err := os.Open(metadataPath)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if v, ok := strings.CutPrefix(line, "Name: "); ok && name == "" {
			name = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "Version: "); ok && version == "" {
			version = strings.TrimSpace(v)
		}
		if name != "" && version != "" {
			break
		}
	}
	return name, version, scanner.Err()
}

// DetectPythonPackage inspects a directory that may be a *.dist-info or
// *.egg-info metadata directory and, if so, parses the package it describes.
// ok is false (with a nil error) when dirPath is neither kind of directory.
func DetectPythonPackage(dirPath string) (FoundPackage, bool, error) {
	base := filepath.Base(dirPath)

	var metadataFile string
	switch {
	case strings.HasSuffix(base, ".dist-info"):
		metadataFile = "METADATA"
	case strings.HasSuffix(base, ".egg-info"):
		metadataFile = "PKG-INFO"
	default:
		return FoundPackage{}, false, nil
	}

	name, version, err := ParsePackageMetadata(filepath.Join(dirPath, metadataFile))
	if err != nil {
		return FoundPackage{}, false, err
	}
	if name == "" || version == "" {
		return FoundPackage{}, false, nil
	}

	return FoundPackage{
		Ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI,
		Name:      name,
		Version:   version,
		Path:      dirPath,
	}, true, nil
}
