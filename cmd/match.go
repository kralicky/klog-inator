package cmd

import (
	"fmt"

	"github.com/kralicky/klog-inator/pkg/inator"
	"github.com/spf13/cobra"
)

var searchList, logArchive string

// matchCmd represents the search command
var matchCmd = &cobra.Command{
	Use:   "match",
	Args:  cobra.NoArgs,
	Short: "Match an existing log archive against a search list",
	Run: func(cmd *cobra.Command, args []string) {
		sl, err := inator.LoadSearchList(searchList)
		if err != nil {
			panic(err)
		}
		sm, collisions := sl.GenerateSearchMap()
		fmt.Printf("%d fingerprinted logs\n", len(sm))
		fmt.Printf("%d collisions\n", len(collisions))

		results := inator.Match(sm, logArchive)

		hit, _ := inator.AnalyzeResults(sm, results)
		fmt.Printf("Hit %.2f%% of log statements\n", hit*100)
	},
}

func init() {
	rootCmd.AddCommand(matchCmd)
	matchCmd.Flags().StringVarP(&searchList, "search-list", "s", "", "Search list to use (output of search --json)")
	matchCmd.Flags().StringVarP(&logArchive, "log-archive", "l", "", "Log archive to search through")
	matchCmd.MarkFlagRequired("search-list")
	matchCmd.MarkFlagRequired("log-archive")
}
