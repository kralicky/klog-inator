package inator

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"

	"go.uber.org/atomic"

	"github.com/sirupsen/logrus"
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

var numMatched = atomic.NewInt32(0)
var numNotMatched = atomic.NewInt32(0)

type MatcherResults = map[*LogStatement]*[]ParsedLog

func matcher(sm SearchMap, parsed <-chan ParsedLog) MatcherResults {
	matched := MatcherResults{}
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

func Match(sm SearchMap, archive string) MatcherResults {
	workerCount := runtime.NumCPU()

	wg := sync.WaitGroup{}
	wg.Add(workerCount)
	defer wg.Wait()

	lines := make(chan []byte, workerCount)
	parsed := make(chan ParsedLog, workerCount)
	go func() {
		wg.Wait()
		close(parsed)
	}()

	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg.Done()
			scanner(lines, parsed)
		}()
	}

	f, err := os.Open(archive)
	if err != nil {
		logrus.Error(err)
		return nil
	}
	defer f.Close()

	wg2 := sync.WaitGroup{}
	wg2.Add(workerCount)
	results := make(chan MatcherResults, workerCount)
	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg2.Done()
			results <- matcher(sm, parsed)
		}()
	}

	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := []byte(scan.Text())
		lines <- line
	}
	close(lines)
	if err := scan.Err(); err != nil {
		logrus.Error(err)
	}
	wg2.Wait()
	close(results)
	fmt.Println("done.")
	fmt.Println("matched:", numMatched.Load())
	fmt.Println("not matched:", numNotMatched.Load())

	merged := MatcherResults{}
	for r := range results {
		for k, v := range r {
			if s, ok := merged[k]; !ok {
				merged[k] = v
			} else {
				*s = append(*s, *v...)
			}
		}
	}

	return merged
}

func AnalyzeResults(sm SearchMap, results MatcherResults) (hit, missed float64) {
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
