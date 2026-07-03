//go:build windows

package ecoscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldSkipDirWindows(t *testing.T) {
	cases := []struct {
		path string
		skip bool
	}{
		{`C:\Windows`, true},
		{`C:\Windows\System32`, false}, // only the exact suffix match at the boundary is pruned; System32 is under Windows already skipped by the parent, so this case documents current single-suffix matching behavior
		{`C:\Program Files\WindowsApps`, true},
		{`C:\$Recycle.Bin`, true},
		{`C:\System Volume Information`, true},
		{`D:\projects\myapp\node_modules`, false},
		{`C:\Users\dev\code`, false},
	}
	for _, c := range cases {
		assert.Equal(t, c.skip, ShouldSkipDir(c.path), c.path)
	}
}
