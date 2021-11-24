package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/kralicky/klog-inator/pkg/inator"
	"github.com/spf13/cobra"
)

var searchList, logArchive, jsonField string

func forEachVerbosityLevel(hit, missed map[int]int64, pct map[int]float64, fn func(string, int64, int64, float64)) {
	for i := -1; i < 10; i++ {
		if _, ok := pct[i]; !ok {
			continue
		}
		if hit[i] == 0 && missed[i] == 0 {
			continue
		}
		vStr := fmt.Sprint(i)
		if i == -1 {
			vStr = "*"
		}
		fn(vStr, hit[i], missed[i], pct[i])
	}
}

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
		if len(collisions) > 0 {
			for _, items := range collisions {
				arrow := "==>"
				for _, item := range items {
					fmt.Printf("%s %s:%d: %s\n", arrow, item.SourceFile, item.LineNumber, item.FormatString)
					arrow = "   "
				}
			}
		}
		options := []inator.MatchOption{}
		if jsonField != "" {
			options = append(options, inator.WithJSONField(jsonField))
		}
		startTime := time.Now()
		results, err := inator.Match(sm, logArchive, options...)
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

		analysis := inator.AnalyzeMatches(sm, aggregated)
		fmt.Printf("=> Hit %4d/%-4d (%05.1f%%) of all statements\n", analysis.NumHitTotal, analysis.NumMissedTotal, analysis.PercentHitTotal)

		forEachVerbosityLevel(analysis.NumInfoHit, analysis.NumInfoMissed, analysis.PercentInfoHit,
			func(v string, hit, missed int64, pct float64) {
				fmt.Printf("=> Hit %4d/%-4d (%05.1f%%) of INFO  [V=%s] statements\n", hit, missed, pct, v)
			})
		fmt.Printf("=> Hit %4d/%-4d (%05.1f%%) of WARNING statements\n", analysis.NumWarnHit, analysis.NumWarnMissed, analysis.PercentWarnHit)
		forEachVerbosityLevel(analysis.NumErrorHit, analysis.NumErrorMissed, analysis.PercentErrorHit,
			func(v string, hit, missed int64, pct float64) {
				fmt.Printf("=> Hit %4d/%-4d (%05.1f%%) of ERROR [v=%s] statements\n", hit, missed, pct, v)
			})
		fmt.Printf("=> Hit %4d/%-4d (%05.1f%%) of FATAL statements\n", analysis.NumFatalHit, analysis.NumFatalMissed, analysis.PercentFatalHit)

		sorted := inator.SortMatches(aggregated)
		if len(sorted) == 0 {
			return
		}
		fmt.Println("=> Top 20 matches:")
		maxHitsLen := 0
		maxFilenameLen := 0

		for i := 0; i < 20; i++ {
			if l := len(fmt.Sprint(len(sorted[i].Hits))); l > maxHitsLen {
				maxHitsLen = l
			}
			if l := len(sorted[i].Log.ShortSourceFile()); l > maxFilenameLen {
				maxFilenameLen = l
			}
		}
		for i := 0; i < 20; i++ {
			fmt.Printf("%2d [%*d hits] [%s]: %*s: %s\n",
				i+1,
				maxHitsLen, len(sorted[i].Hits),
				sorted[i].Log.Severity.String(),
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
	matchCmd.Flags().StringVar(&jsonField, "json-field", "", "If the logs are in JSON format, read the log message from this field.")
	matchCmd.MarkFlagRequired("search-list")
	matchCmd.MarkFlagRequired("log-archive")
}
