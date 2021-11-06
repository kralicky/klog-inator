package inator_test

import (
	"regexp"
	"testing"

	"github.com/kralicky/klog-inator/pkg/inator"
)

var (
	SampleLine = []byte("I1105 13:30:39.614388  739568 queueset/queueset.go:488] Sample Text")
)

func BenchmarkParseLine(b *testing.B) {
	for i := 0; i < b.N; i++ {
		inator.ParseLine(SampleLine)
	}
}

func BenchmarkParseLineRegex(b *testing.B) {
	rx, err := regexp.Compile(`^([IWEF])\d{4}\s[0-2]\d(?:\:[0-5]\d){2}\.\d{6}\s[\s\d]{7}\s([a-zA-Z0-9-_\.]+?)\/([a-zA-Z0-9-_\.]+?\.go)\:(\d+?)\]`)
	if err != nil {
		panic(err)
	}
	for i := 0; i < b.N; i++ {
		rx.Match(SampleLine)
	}
}
