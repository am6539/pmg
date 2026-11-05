package flows

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeFakeExecutable creates an executable in dir named name that appends its
// received arguments as a single line to logPath, then exits with exitCode.
func writeFakeExecutable(t *testing.T, dir, name, logPath string, exitCode int) {
	t.Helper()

	if runtime.GOOS == "windows" {
		scriptPath := filepath.Join(dir, name+".cmd")
		content := "@echo off\r\necho %* >> \"" + logPath + "\"\r\nexit /b " + itoa(exitCode) + "\r\n"
		require.NoError(t, os.WriteFile(scriptPath, []byte(content), 0o755))
		return
	}

	scriptPath := filepath.Join(dir, name)
	content := "#!/bin/sh\necho \"$@\" >> \"" + logPath + "\"\nexit " + itoa(exitCode) + "\n"
	require.NoError(t, os.WriteFile(scriptPath, []byte(content), 0o755))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}

// withFakePATH isolates PATH to dir only, so lookups can't accidentally
// resolve to a real package manager binary installed on the host.
func withFakePATH(t *testing.T, dir string) {
	t.Helper()
	original := os.Getenv("PATH")
	require.NoError(t, os.Setenv("PATH", dir))
	t.Cleanup(func() {
		_ = os.Setenv("PATH", original)
	})
}

func TestClearPackageManagerCache_PassesExpectedArgs(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "npm.log")
	writeFakeExecutable(t, dir, "npm", logPath, 0)
	withFakePATH(t, dir)

	clearPackageManagerCache(context.Background(), "npm")

	out, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Equal(t, "cache clean --force", strings.TrimSpace(string(out)))
}

// A pmg shim earlier on PATH must not be invoked, otherwise the cache clean
// re-enters pmg, which runs the cache clean again, recursing without bound.
func TestClearPackageManagerCache_BypassesPMGShim(t *testing.T) {
	for pm, args := range packageManagerCacheCleanArgs {
		t.Run(pm, func(t *testing.T) {
			shimDir := filepath.Join(t.TempDir(), ".pmg", "bin")
			require.NoError(t, os.MkdirAll(shimDir, 0o755))
			realDir := t.TempDir()
			shimLog := filepath.Join(shimDir, "shim.log")
			realLog := filepath.Join(realDir, "real.log")

			writeFakeExecutable(t, shimDir, pm, shimLog, 0)
			writeFakeExecutable(t, realDir, pm, realLog, 0)
			withFakePATH(t, shimDir+string(os.PathListSeparator)+realDir)

			clearPackageManagerCache(context.Background(), pm)

			assert.NoFileExists(t, shimLog, "pmg shim must not be invoked")

			out, err := os.ReadFile(realLog)
			require.NoError(t, err)
			assert.Equal(t, strings.Join(args, " "), strings.TrimSpace(string(out)))
		})
	}
}

func TestClearPackageManagerCache_UnknownPackageManager_NoOp(t *testing.T) {
	dir := t.TempDir()
	withFakePATH(t, dir)

	assert.NotPanics(t, func() {
		clearPackageManagerCache(context.Background(), "not-a-real-package-manager")
	})
}

func TestClearPackageManagerCache_CommandFails_DoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "pip.log")
	writeFakeExecutable(t, dir, "pip", logPath, 1)
	withFakePATH(t, dir)

	assert.NotPanics(t, func() {
		clearPackageManagerCache(context.Background(), "pip")
	})

	out, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Equal(t, "cache purge", strings.TrimSpace(string(out)))
}

func TestClearPackageManagerCache_MissingBinary_DoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	withFakePATH(t, dir)

	assert.NotPanics(t, func() {
		clearPackageManagerCache(context.Background(), "uv")
	})
}
