package cmd

import (
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/kralicky/klog-inator/pkg/inator"
	"github.com/spf13/cobra"
)

var searchList, logArchive, jsonField string
var severityFilter, verbosityFilter []string
var showAll, missed, fullPaths bool
var top int

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
		aggregated := inator.AggregateResults(results.Matched)

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
		if showAll {
			top = len(sorted)
			fmt.Println("=> All matches:")
		} else {
			fmt.Printf("=> Top %d matches:\n", top)
		}
		printEntries(sorted[:top])

		if missed {
			fmt.Println("=> Missed logs:")
			logs := inator.FindMissed(sm, aggregated)
			printEntries(inator.SortMatches(logs))
		}
	},
}

func printEntries(entries []inator.MatchEntry) {
	maxHitsLen := 0
	maxFilenameLen := 0

	formatFilename := func(log *inator.LogStatement) string {
		return log.ShortSourceFile() + ":" + fmt.Sprint(log.LineNumber)
	}
	if fullPaths {
		formatFilename = func(log *inator.LogStatement) string {
			return log.SourceFile + ":" + fmt.Sprint(log.LineNumber)
		}
	}

	for i := 0; i < len(entries); i++ {
		if l := len(fmt.Sprint(len(entries[i].Hits))); l > maxHitsLen {
			maxHitsLen = l
		}
		if l := len(formatFilename(entries[i].Log)); l > maxFilenameLen {
			maxFilenameLen = l
		}
	}

	maxIndexLen := int64(math.Log10(float64(len(entries))) + 1)
	var severityFilterMap map[inator.Severity]bool

	if len(severityFilter) > 0 {
		severityFilterMap = map[inator.Severity]bool{
			inator.SeverityInfo:    false,
			inator.SeverityWarning: false,
			inator.SeverityError:   false,
			inator.SeverityFatal:   false,
		}
		for _, f := range severityFilter {
			switch strings.ToLower(f) {
			case "info", "debug", "i", "0":
				severityFilterMap[inator.SeverityInfo] = true
			case "warn", "warning", "w", "1":
				severityFilterMap[inator.SeverityWarning] = true
			case "error", "err", "e", "2":
				severityFilterMap[inator.SeverityError] = true
			case "fatal", "f", "3":
				severityFilterMap[inator.SeverityFatal] = true
			}
		}
	} else {
		severityFilterMap = map[inator.Severity]bool{
			inator.SeverityInfo:    true,
			inator.SeverityWarning: true,
			inator.SeverityError:   true,
			inator.SeverityFatal:   true,
		}
	}

	for i := 0; i < len(entries); i++ {
		entry := entries[i]
		if !severityFilterMap[entry.Log.Severity] {
			continue
		}
		fmt.Printf("%*d [%*d hits] [%s]: %*s: %s\n",
			maxIndexLen, i+1,
			maxHitsLen, len(entry.Hits),
			entry.Log.Severity.String(),
			maxFilenameLen, formatFilename(entry.Log),
			entry.Log.FormatString,
		)
	}
}

func init() {
	rootCmd.AddCommand(matchCmd)
	matchCmd.Flags().StringVarP(&searchList, "search-list", "s", "", "Search list to use (output of search --json)")
	matchCmd.Flags().StringVarP(&logArchive, "log-archive", "l", "", "Log archive to search through")
	matchCmd.Flags().StringVar(&jsonField, "json-field", "", "If the logs are in JSON format, read the log message from this field.")
	matchCmd.Flags().BoolVar(&showAll, "all", false, "Show all matches instead of a limited number of top matches")
	matchCmd.Flags().IntVar(&top, "top", 20, "Number of top matches to show (if --all is given, this is ignored)")
	matchCmd.Flags().BoolVar(&missed, "missed", false, "Also show log messages with 0 matches")
	matchCmd.Flags().BoolVar(&fullPaths, "full-paths", false, "Show full paths of source files")
	matchCmd.Flags().StringSliceVar(&severityFilter, "severity", []string{}, "Only show log statements with these severity levels")
	matchCmd.MarkFlagRequired("search-list")
	matchCmd.MarkFlagRequired("log-archive")
}
