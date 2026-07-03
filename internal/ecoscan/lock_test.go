package ecoscan

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcquireLockSucceedsWhenNoLockExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ecoscan.lock")

	release, ok, err := AcquireLock(path)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, release)

	_, statErr := os.Stat(path)
	assert.NoError(t, statErr)

	release()
	_, statErr = os.Stat(path)
	assert.True(t, os.IsNotExist(statErr))
}

func TestAcquireLockFailsWhenFreshLockHeld(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ecoscan.lock")
	require.NoError(t, os.WriteFile(path, []byte("12345"), 0o600))

	release, ok, err := AcquireLock(path)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, release)
}

func TestAcquireLockReclaimsStaleLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ecoscan.lock")
	require.NoError(t, os.WriteFile(path, []byte("12345"), 0o600))

	staleTime := time.Now().Add(-3 * time.Hour)
	require.NoError(t, os.Chtimes(path, staleTime, staleTime))

	release, ok, err := AcquireLock(path)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, release)
	release()
}
