package cmd

import (
	"fmt"
	"os"
	"time"

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
		fmt.Printf("Loaded search list with %d logs\n", len(sl))
		fmt.Println("Computing log fingerprints...")
		sm, collisions := sl.GenerateSearchMap()
		fmt.Printf("=> Computed %d unique log fingerprints\n", len(sm))
		fmt.Printf("=> %d collisions\n", len(collisions))

		startTime := time.Now()
		results, err := inator.Match(sm, logArchive)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		duration := time.Since(startTime)
		fmt.Printf("=> Processed %d logs in %s (%d logs/s)\n",
			results.NumMatched+results.NumNotMatched,
			duration.Round(time.Millisecond),
			int64(float64(results.NumMatched)/duration.Seconds()))
		fmt.Printf("=> %d logs matched\n", results.NumMatched)
		fmt.Printf("=> %d logs not matched\n", results.NumNotMatched)

		fmt.Println("Aggregating results...")
		aggregated := inator.AggregateResults(results.Matches)

		hit, _ := inator.AnalyzeMatches(sm, aggregated)
		fmt.Printf("=> Hit %.2f%% of log statements\n", hit*100)

		sorted := inator.SortMatches(aggregated)
		fmt.Println("=> Top 10 matches:")
		maxHitsLen := 0
		maxFilenameLen := 0
		for i := 0; i < 10; i++ {
			if l := len(fmt.Sprint(len(sorted[i].Hits))); l > maxHitsLen {
				maxHitsLen = l
			}
			if l := len(sorted[i].Log.ShortSourceFile()); l > maxFilenameLen {
				maxFilenameLen = l
			}
		}
		for i := 0; i < 10; i++ {
			fmt.Printf("%2d [%*d hits]: %*s: %s\n",
				i+1,
				maxHitsLen, len(sorted[i].Hits),
				maxFilenameLen, sorted[i].Log.ShortSourceFile(),
				sorted[i].Log.FormatString,
			)
		}
	},
}

func init() {
	rootCmd.AddCommand(matchCmd)
	matchCmd.Flags().StringVarP(&searchList, "search-list", "s", "", "Search list to use (output of search --json)")
	matchCmd.Flags().StringVarP(&logArchive, "log-archive", "l", "", "Log archive to search through")
	matchCmd.MarkFlagRequired("search-list")
	matchCmd.MarkFlagRequired("log-archive")
}
