package ecoscan

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// staleLockAfter is how long an ecoscan.lock file can sit untouched before a
// new scan is allowed to reclaim it (covers the case where a previous scan's
// process was killed without releasing the lock).
const staleLockAfter = 2 * time.Hour

// AcquireLock attempts to take the ecosystem-scan lock file at path.
// release is non-nil and ok is true on success; the caller must call
// release() when the scan finishes (typically via defer). If the lock is
// already held and not stale, ok is false and release is nil.
func AcquireLock(path string) (release func(), ok bool, err error) {
	if info, statErr := os.Stat(path); statErr == nil {
		if time.Since(info.ModTime()) < staleLockAfter {
			return nil, false, nil
		}
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			return nil, false, fmt.Errorf("remove stale lock: %w", rmErr)
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("create lock file: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(strconv.Itoa(os.Getpid())); err != nil {
		return nil, false, fmt.Errorf("write lock file: %w", err)
	}

	return func() { os.Remove(path) }, true, nil
}
