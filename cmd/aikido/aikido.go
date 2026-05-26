package aikido

import (
	"github.com/spf13/cobra"
)

func NewAikidoCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aikido",
		Short: "Aikido Intel malware feed operations",
	}

	cmd.AddCommand(newRefreshCommand())

	return cmd
}
