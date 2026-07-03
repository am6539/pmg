//go:build windows

package ecoscan

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootsReturnsAtLeastOneDriveLetter(t *testing.T) {
	roots, err := Roots()
	require.NoError(t, err)
	require.NotEmpty(t, roots)

	drivePattern := regexp.MustCompile(`^[A-Z]:\\$`)
	for _, r := range roots {
		assert.Regexp(t, drivePattern, r)
	}
}
