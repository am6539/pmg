package flows

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/shim"
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

	// Resolve past the pmg shim: invoking it would re-enter pmg, which would run
	// this cache clean again and recurse without bound.
	realBinary, err := shim.ResolveRealBinary(pmName)
	if err != nil {
		log.Warnf("failed to clear %s cache before install (continuing anyway): %v", pmName, err)
		return
	}

	cleanCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cleanCtx, realBinary, args...)
	cmd.Env = shim.FilterPMGFromEnv(os.Environ())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Warnf("failed to clear %s cache before install (continuing anyway): %v: %s", pmName, err, strings.TrimSpace(string(out)))
	}
}
