package inator

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"

	"go.uber.org/atomic"
)

func parseLine(line []byte) (ls ParsedLog, ok bool) {
	// we are looking for a very specific format:
	// Lmmdd hh:mm:ss.uuuuuu thread# file:line] <message>
	// [-------------29------------]

	if len(line) < 29 {
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

	// space
	if line[29] != ' ' {
		return
	}

	// dir/file:
	index := 30
	dir := make([]byte, 0, 255)
	file := make([]byte, 0, 255)
	success := false
	temp := make([]byte, 0, 255)
FILENAME:
	for ; index < len(line); index++ {
		switch c := line[index]; {
		case c == '.' || c == '-' || c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9'):
			temp = append(temp, c)
		case c == '/':
			dir = append(dir, temp...)
			temp = make([]byte, 0, 255)
		case c == ':':
			file = append(file, temp...)
			success = true
			break FILENAME
		default:
			break FILENAME
		}
	}
	if !success {
		return
	}
	ls.SourceFile = filepath.Join(string(dir), string(file))
	index++

	// lineNumber]
	lineNumber := make([]byte, 0, 255)
	success = false
LINENUMBER:
	for ; index < len(line); index++ {
		switch c := line[index]; {
		case c == ']':
			success = len(lineNumber) > 0
			break LINENUMBER
		case c >= '0' && c <= '9':
			lineNumber = append(lineNumber, c)
		default:
			break LINENUMBER
		}
	}
	if !success {
		return
	}
	num, err := strconv.Atoi(string(lineNumber))
	if err != nil {
		return
	}
	ls.LineNumber = num
	index++

	// space
	if line[index] != ' ' {
		return
	}
	index++

	// message
	message := line[index:]
	ls.Message = string(message)
	ok = true
	return
}

func scanner(lines <-chan []byte, parsedLines chan<- ParsedLog) {
	for line := range lines {
		logStmt, ok := parseLine(line)
		if ok {
			parsedLines <- logStmt
		}
	}
}

var numMatched = atomic.NewInt64(0)
var numNotMatched = atomic.NewInt64(0)

type Matches = map[*LogStatement]*[]ParsedLog

func matcher(sm SearchMap, parsed <-chan ParsedLog) Matches {
	matched := Matches{}
	for p := range parsed {
		fp := p.Fingerprint()
		if stmt, ok := sm[fp]; ok {
			if s, ok := matched[stmt]; !ok {
				matched[stmt] = &[]ParsedLog{p}
			} else {
				*s = append(*s, p)
			}
			numMatched.Add(1)
		} else {
			numNotMatched.Add(1)
		}
	}
	return matched
}

type MatchResults struct {
	Matches       []Matches
	NumMatched    int64
	NumNotMatched int64
}

func Match(sm SearchMap, archive string) (MatchResults, error) {
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
	fmt.Printf("Processing archive in %d chunk%s using %d workers\n", len(channelGroups), s, workerCount)
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
			scanner(lines, parsedLines)
		}(channelGroups[i%len(channelGroups)].Lines,
			channelGroups[i%len(channelGroups)].ParsedLines)
		go func(parsedLines <-chan ParsedLog) {
			defer matcherWg.Done()
			results <- matcher(sm, parsedLines)
		}(channelGroups[i%len(channelGroups)].ParsedLines)
	}

	f, err := os.Open(archive)
	info, _ := f.Stat()
	if err != nil {
		return MatchResults{}, err
	}
	defer f.Close()
	buf := make([]byte, info.Size())
	n, err := io.ReadFull(f, buf)
	if err != nil || n != len(buf) {
		panic("could not read archive")
	}
	// chunk the file into len(channelGroups) chunks, cleanly separated by newlines
	chunkSize := len(buf) / len(channelGroups)

	readerWg := sync.WaitGroup{}
	readerWg.Add(len(channelGroups))
	seekPos := 0
	for i := 0; i < len(channelGroups); i++ {
		startByte := seekPos
		seekPos += chunkSize
		if seekPos > len(buf)-1 {
			seekPos = len(buf) - 1
		}
		for seekPos <= len(buf)-1 && buf[seekPos] != '\n' {
			seekPos++
		}
		if seekPos < len(buf)-1 {
			seekPos++
		}
		chunk := buf[startByte:seekPos]
		//fmt.Printf("Chunk %d: %d bytes [%d:%d]\n", i, len(chunk), startByte, seekPos)
		go func(chunk []byte, linesCh chan []byte) {
			defer readerWg.Done()
			scan := bufio.NewScanner(bytes.NewReader(chunk))
			for scan.Scan() {
				line := []byte(scan.Text())
				linesCh <- line
			}
			if err := scan.Err(); err != nil {
				panic(err)
			}
			close(linesCh)
		}(chunk, channelGroups[i].Lines)
	}
	readerWg.Wait()
	scannerWg.Wait()
	matcherWg.Wait()

	close(results)

	matches := []Matches{}
	for match := range results {
		matches = append(matches, match)
	}
	return MatchResults{
		Matches:       matches,
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

func AnalyzeMatches(sm SearchMap, results Matches) (hit, missed float64) {
	numHit := 0
	numMissed := 0
	for _, v := range sm {
		matched, ok := results[v]
		if !ok || matched == nil {
			numMissed++
		} else {
			numHit++
		}
	}

	return float64(numHit) / float64(len(sm)), float64(numMissed) / float64(len(sm))
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
			Log:  k,
			Hits: *v,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return len(entries[i].Hits) > len(entries[j].Hits)
	})

	return entries
}
