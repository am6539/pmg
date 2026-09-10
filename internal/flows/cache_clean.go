package flows

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/safedep/dry/log"
)

// packageManagerCacheCleanArgs maps a package manager's CommandName to the
// arguments that clear its local tarball/wheel cache.
var packageManagerCacheCleanArgs = map[string][]string{
	"npm":    {"cache", "clean", "--force"},
	"pnpm":   {"store", "prune"},
	"yarn":   {"cache", "clean"},
	"bun":    {"pm", "cache", "rm"},
	"pip":    {"cache", "purge"},
	"pip3":   {"cache", "purge"},
	"uv":     {"cache", "clean"},
	"poetry": {"cache", "clear", "PyPI", "--all"},
}

// clearPackageManagerCache best-effort clears the local tarball/wheel cache for
// pmName so that a subsequent install cannot be served from disk, bypassing the
// proxy's MITM analysis. Failures are logged and swallowed — this must never
// block the actual install.
func clearPackageManagerCache(ctx context.Context, pmName string) {
	args, ok := packageManagerCacheCleanArgs[pmName]
	if !ok {
		return
	}

	cleanCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cleanCtx, pmName, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Warnf("failed to clear %s cache before install (continuing anyway): %v: %s", pmName, err, strings.TrimSpace(string(out)))
	}
}
