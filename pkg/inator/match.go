package inator

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"

	"github.com/kralicky/klog-inator/pkg/fast"
	"github.com/valyala/fastjson"
	"go.uber.org/atomic"
)

func ParseLine(line []byte) (ls ParsedLog, ok bool) {
	// we are looking for a very specific format:
	// Lmmdd hh:mm:ss.uuuuuu thread# file:line] <message>
	// [-------------29------------]

	if len(line) <= 29 {
		return
	}

	// check that spaces exist in the expected locations
	if line[5] != ' ' || line[21] != ' ' || line[29] != ' ' {
		return
	}

	// L
	severity := line[0]
	switch severity {
	case 'I':
		ls.Severity = 0
	case 'W':
		ls.Severity = 1
	case 'E':
		ls.Severity = 2
	case 'F':
		ls.Severity = 3
	default:
		return
	}

	// mmdd
	mmdd := line[1:5]
	if mmdd[0] < '0' || mmdd[0] > '1' {
		return
	}
	if mmdd[1] < '0' || mmdd[1] > '9' {
		return
	}
	if mmdd[2] < '0' || mmdd[2] > '3' {
		return
	}
	if mmdd[3] < '0' || mmdd[3] > '9' {
		return
	}

	// hh:mm:ss.uuuuuu
	hhmmss := line[6:21]
	if hhmmss[0] < '0' || hhmmss[0] > '2' {
		return
	}
	if hhmmss[1] < '0' || hhmmss[1] > '9' {
		return
	}
	if hhmmss[2] != ':' {
		return
	}
	if hhmmss[3] < '0' || hhmmss[3] > '5' {
		return
	}
	if hhmmss[4] < '0' || hhmmss[4] > '9' {
		return
	}
	if hhmmss[5] != ':' {
		return
	}
	if hhmmss[6] < '0' || hhmmss[6] > '5' {
		return
	}
	if hhmmss[7] < '0' || hhmmss[7] > '9' {
		return
	}
	if hhmmss[8] != '.' {
		return
	}
	for i := 9; i < len(hhmmss); i++ {
		if hhmmss[i] < '0' || hhmmss[i] > '9' {
			return
		}
	}

	// threadid (7 characters left-padded with spaces)
	threadid := line[22:29]
	matchSpaces := true
	for i := 0; i < 7; i++ {
		if matchSpaces {
			if threadid[i] != ' ' {
				matchSpaces = false
			} else {
				continue
			}
		}
		if threadid[i] < '0' || threadid[i] > '9' {
			return
		}
	}

	// dir/file:
	index := 30
	dirStart := 30
	var dirEnd, fileStart, fileEnd int

FILENAME:
	for ; index < len(line)-1; index++ {
		switch c := line[index]; {
		case c == '.' || c == '-' || c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9'):
		case c == '/':
			dirEnd = index
			fileStart = index + 1
		case c == ':':
			fileEnd = index
			break FILENAME
		default:
			break FILENAME
		}
	}
	if index == len(line)-1 || dirEnd-dirStart < 1 ||
		fileStart != dirEnd+1 || fileEnd-fileStart < 1 {
		return
	}
	index++

	// lineNumber]
	lineNumStart := index
	var lineNumEnd int
LINENUMBER:
	for ; index < len(line)-1; index++ {
		switch c := line[index]; {
		case c >= '0' && c <= '9':
		case c == ']':
			lineNumEnd = index
			break LINENUMBER
		default:
			break LINENUMBER
		}
	}
	if index == len(line)-1 || lineNumEnd-lineNumStart < 1 {
		return
	}
	index++

	// space
	if line[index] != ' ' {
		return
	}
	index++

	// message
	messageStart := index
	messageEnd := len(line) - 1
	var err error
	ls.LineNumber, err = strconv.Atoi(string(line[lineNumStart:lineNumEnd]))
	if err != nil {
		ok = false
	}
	ls.SourceFile = string(line[dirStart:fileEnd])
	ls.Message = string(line[messageStart:messageEnd])
	ok = true
	return
}

func scanner(lines <-chan []byte, parsedLines chan<- ParsedLog, jsonField string) {
	if jsonField == "" {
		for line := range lines {
			logStmt, ok := ParseLine(line)
			if ok {
				parsedLines <- logStmt
			}
		}
	} else {
		for line := range lines {
			msg := fastjson.GetBytes(line, jsonField)
			if msg == nil {
				continue
			}
			logStmt, ok := ParseLine(msg)
			if ok {
				parsedLines <- logStmt
			}
		}
	}
}

var numMatched = atomic.NewInt64(0)
var numNotMatched = atomic.NewInt64(0)

type Matches = map[*LogStatement]*[]ParsedLog

func matcher(sm SearchMap, parsed <-chan ParsedLog) Matches {
	hit := Matches{}
	for p := range parsed {
		fp := p.Fingerprint()
		if stmt, ok := sm[fp]; ok {
			if s, ok := hit[stmt]; !ok {
				hit[stmt] = &[]ParsedLog{p}
			} else {
				*s = append(*s, p)
			}
			numMatched.Add(1)
		} else {
			numNotMatched.Add(1)
		}
	}
	return hit
}

type MatchedAndNotMatchedLogs struct {
	Matched    Matches
	NotMatched Matches
}

type MatchResults struct {
	Matched       []Matches
	NotMatched    []Matches
	NumMatched    int64
	NumNotMatched int64
}

type MatchOptions struct {
	jsonField string
}

type MatchOption func(*MatchOptions)

func (o *MatchOptions) Apply(opts ...MatchOption) {
	for _, op := range opts {
		op(o)
	}
}

func WithJSONField(field string) MatchOption {
	return func(o *MatchOptions) {
		o.jsonField = field
	}
}

func Match(sm SearchMap, archive string, opts ...MatchOption) (MatchResults, error) {
	options := MatchOptions{}
	options.Apply(opts...)

	workerCount := runtime.NumCPU()
	workersPerGroup := 4
	channelGroups := make([]struct {
		Lines       chan []byte
		ParsedLines chan ParsedLog
	}, workerCount/workersPerGroup)
	s := "s"
	if len(channelGroups) == 1 {
		s = ""
	}
	info, err := os.Lstat(archive)
	if err != nil {
		return MatchResults{}, err
	}
	fmt.Printf("Processing %.2fGB archive in %d chunk%s using %d workers\n",
		float64(info.Size())/1024.0/1024.0/1024.0,
		len(channelGroups), s, workerCount)
	scannerWg := sync.WaitGroup{}
	scannerWg.Add(workerCount)
	matcherWg := sync.WaitGroup{}
	matcherWg.Add(workerCount)

	for i := 0; i < len(channelGroups); i++ {
		channelGroups[i].Lines = make(chan []byte, workerCount)
		channelGroups[i].ParsedLines = make(chan ParsedLog, workerCount)
	}
	go func() {
		scannerWg.Wait()
		for _, group := range channelGroups {
			close(group.ParsedLines)
		}
	}()

	results := make(chan Matches, workerCount)

	for i := 0; i < workerCount; i++ {
		go func(lines <-chan []byte, parsedLines chan<- ParsedLog) {
			defer scannerWg.Done()
			scanner(lines, parsedLines, options.jsonField)
		}(channelGroups[i%len(channelGroups)].Lines,
			channelGroups[i%len(channelGroups)].ParsedLines)
		go func(parsedLines <-chan ParsedLog) {
			defer matcherWg.Done()
			results <- matcher(sm, parsedLines)
		}(channelGroups[i%len(channelGroups)].ParsedLines)
	}

	channels := make([]chan []byte, len(channelGroups))
	for i := 0; i < len(channels); i++ {
		channels[i] = channelGroups[i].Lines
	}
	if err := fast.ReadLines(archive, channels); err != nil {
		return MatchResults{}, err
	}

	scannerWg.Wait()
	matcherWg.Wait()

	close(results)

	hit := []Matches{}
	for match := range results {
		hit = append(hit, match)
	}
	return MatchResults{
		Matched:       hit,
		NumMatched:    numMatched.Load(),
		NumNotMatched: numNotMatched.Load(),
	}, nil
}

func AggregateResults(results []Matches) Matches {
	first := results[0]
	for _, result := range results[1:] {
		for k, v := range result {
			if s, ok := first[k]; !ok {
				first[k] = v
			} else {
				*s = append(*s, *v...)
			}
		}
	}
	return first
}

func FindMissed(sm SearchMap, aggregated Matches) Matches {
	missed := Matches{}
	for _, v := range sm {
		if _, ok := aggregated[v]; !ok {
			missed[v] = nil
		}
	}
	return missed
}

type AnalyzeResult struct {
	NumHitTotal     int64
	NumMissedTotal  int64
	PercentHitTotal float64
	NumInfoHit      map[int]int64
	NumInfoMissed   map[int]int64
	PercentInfoHit  map[int]float64
	NumWarnHit      int64
	NumWarnMissed   int64
	PercentWarnHit  float64
	NumErrorHit     map[int]int64
	NumErrorMissed  map[int]int64
	PercentErrorHit map[int]float64
	NumFatalHit     int64
	NumFatalMissed  int64
	PercentFatalHit float64
}

func AnalyzeMatches(sm SearchMap, results Matches) AnalyzeResult {
	result := AnalyzeResult{
		NumInfoHit:      make(map[int]int64),
		NumInfoMissed:   make(map[int]int64),
		PercentInfoHit:  make(map[int]float64),
		NumErrorHit:     make(map[int]int64),
		NumErrorMissed:  make(map[int]int64),
		PercentErrorHit: make(map[int]float64),
	}
	for _, v := range sm {
		matched, ok := results[v]
		verbosity := -1
		if v.Verbosity != nil {
			verbosity = *v.Verbosity
		}
		if !ok || matched == nil || len(*matched) == 0 {
			result.NumMissedTotal++
			switch v.Severity {
			case SeverityInfo:
				result.NumInfoMissed[verbosity]++
			case SeverityWarning:
				result.NumWarnMissed++
			case SeverityError:
				result.NumErrorMissed[verbosity]++
			case SeverityFatal:
				result.NumFatalMissed++
			}
		} else {
			result.NumHitTotal++
			switch v.Severity {
			case SeverityInfo:
				result.NumInfoHit[verbosity]++
			case SeverityWarning:
				result.NumWarnHit++
			case SeverityError:
				result.NumErrorHit[verbosity]++
			case SeverityFatal:
				result.NumFatalHit++
			}
		}
	}
	result.PercentHitTotal = float64(result.NumHitTotal) / float64(result.NumHitTotal+result.NumMissedTotal) * 100
	for k, v := range result.NumInfoHit {
		result.PercentInfoHit[k] = float64(v) / float64(result.NumInfoHit[k]+result.NumInfoMissed[k]) * 100
	}
	for k := range result.NumInfoMissed {
		result.PercentInfoHit[k] = float64(result.NumInfoHit[k]) / float64(result.NumInfoHit[k]+result.NumInfoMissed[k]) * 100
	}
	result.PercentWarnHit = float64(result.NumWarnHit) / float64(result.NumWarnHit+result.NumWarnMissed) * 100
	for k, v := range result.NumErrorHit {
		result.PercentErrorHit[k] = float64(v) / float64(result.NumErrorHit[k]+result.NumErrorMissed[k]) * 100
	}
	for k := range result.NumErrorMissed {
		result.PercentErrorHit[k] = float64(result.NumErrorHit[k]) / float64(result.NumErrorHit[k]+result.NumErrorMissed[k]) * 100
	}
	result.PercentFatalHit = float64(result.NumFatalHit) / float64(result.NumFatalHit+result.NumFatalMissed) * 100
	return result
}

type MatchEntry struct {
	Log  *LogStatement
	Hits []ParsedLog
}

// Sorts matches by number of hits
func SortMatches(results Matches) []MatchEntry {
	entries := make([]MatchEntry, 0, len(results))
	for k, v := range results {
		entries = append(entries, MatchEntry{
			Log: k,
			Hits: func(v *[]ParsedLog) []ParsedLog {
				if v == nil {
					return []ParsedLog{}
				}
				return *v
			}(v),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if len(entries[i].Hits) == len(entries[j].Hits) {
			return entries[i].Log.SourceFile > entries[j].Log.SourceFile
		}
		return len(entries[i].Hits) > len(entries[j].Hits)
	})

	return entries
}
