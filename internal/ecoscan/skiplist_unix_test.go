//go:build darwin

package ecoscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldSkipDirDarwin(t *testing.T) {
	cases := []struct {
		path string
		skip bool
	}{
		{"/proc", true},
		{"/sys", true},
		{"/dev", true},
		{"/run", true},
		{"/System", true},
		{"/private/var/vm", true},
		{"/home/dev/code", false},
		{"/Users/dev/projects/app/node_modules", false},
	}
	for _, c := range cases {
		assert.Equal(t, c.skip, ShouldSkipDir(c.path), c.path)
	}
}

