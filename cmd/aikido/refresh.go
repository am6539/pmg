package aikido

import (
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/ui"
	"github.com/spf13/cobra"
)

func newRefreshCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "refresh",
		Short: "Pre-fetch and cache the Aikido Intel malware feeds",
		Long: `Force an immediate download of both the npm and PyPI Aikido malware feeds,
bypassing the TTL. Useful in CI pipelines to warm the cache before running
package installs so that analysis adds no latency.`,
		RunE: runRefresh,
	}
}

func runRefresh(cmd *cobra.Command, _ []string) error {
	cfg := config.Get()

	if !cfg.Config.AikidoIntel.Enabled {
		ui.Infof("Aikido Intel is disabled in config (aikido_intel.enabled: false)")
		return nil
	}

	ui.SetStatus("Refreshing Aikido Intel malware feeds...")
	defer ui.ClearStatus()

	an, err := analyzer.NewAikidoIntelAnalyzer(analyzer.AikidoIntelAnalyzerConfig{
		BaseURL:     cfg.Config.AikidoIntel.BaseURL,
		CacheDir:    cfg.AikidoCacheDir(),
		CacheTTL:    cfg.Config.AikidoIntel.CacheTTL,
		HTTPTimeout: cfg.Config.AikidoIntel.RequestTimeout,
	})
	if err != nil {
		return err
	}

	if err := an.Refresh(cmd.Context()); err != nil {
		return err
	}

	ui.Successf("Aikido Intel feeds refreshed and cached at %s", cfg.AikidoCacheDir())
	return nil
}
