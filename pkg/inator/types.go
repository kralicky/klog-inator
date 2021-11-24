package inator

import (
	"crypto/sha1"
	"encoding/hex"
	"path/filepath"
	"strconv"

	"golang.org/x/tools/go/packages"
)

type Severity int32

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityError
	SeverityFatal
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "I"
	case SeverityWarning:
		return "W"
	case SeverityError:
		return "E"
	case SeverityFatal:
		return "F"
	default:
		return "?"
	}
}

type LogStatement struct {
	SourceFile   string   `json:"sourceFile"`
	LineNumber   int      `json:"lineNumber"`
	Severity     Severity `json:"severity"`
	Verbosity    *int     `json:"verbosity,omitempty"`
	FormatString string   `json:"formatString,omitempty"`
}

type ParsedLog struct {
	SourceFile string `json:"sourceFile"`
	LineNumber int    `json:"lineNumber"`
	Severity   int32  `json:"severity"`
	Message    string `json:"message"`
}

func (s LogStatement) ShortSourceFile() string {
	return filepath.Join(filepath.Base(filepath.Dir(s.SourceFile)), filepath.Base(s.SourceFile))
}

func (s LogStatement) Fingerprint() string {
	// To compute the fingerprint, hash the source file name with its immediate
	// parent directory, the line number, and severity.
	h := sha1.New()
	h.Write([]byte(s.ShortSourceFile()))
	h.Write([]byte(strconv.Itoa(s.LineNumber)))
	h.Write([]byte(strconv.Itoa(int(s.Severity))))
	return hex.EncodeToString(h.Sum(nil))
}

func (s ParsedLog) Fingerprint() string {
	h := sha1.New()
	h.Write([]byte(s.SourceFile))
	h.Write([]byte(strconv.Itoa(s.LineNumber)))
	h.Write([]byte(strconv.Itoa(int(s.Severity))))
	return hex.EncodeToString(h.Sum(nil))
}

type internalPackage struct {
	Dir           string           // directory containing package sources
	ImportPath    string           // import path of package in dir
	ImportComment string           // path in import comment on package statement
	Name          string           // package name
	Doc           string           // package documentation string
	Target        string           // install path
	Shlib         string           // the shared library that contains this package (only set when -linkshared)
	Goroot        bool             // is this package in the Go root?
	Standard      bool             // is this package part of the standard Go library?
	Stale         bool             // would 'go install' do anything for this package?
	StaleReason   string           // explanation for Stale==true
	Root          string           // Go root or Go path dir containing this package
	ConflictDir   string           // this directory shadows Dir in $GOPATH
	BinaryOnly    bool             // binary-only package (no longer supported)
	ForTest       string           // package is only for use in named test
	Export        string           // file containing export data (when using -export)
	BuildID       string           // build ID of the compiled package (when using -export)
	Module        *packages.Module // info about package's containing module, if any (can be nil)
	Match         []string         // command-line patterns matching this package
	DepOnly       bool             // package is only a dependency, not explicitly listed

	// Source files
	GoFiles           []string // .go source files (excluding CgoFiles, TestGoFiles, XTestGoFiles)
	CgoFiles          []string // .go source files that import "C"
	CompiledGoFiles   []string // .go files presented to compiler (when using -compiled)
	IgnoredGoFiles    []string // .go source files ignored due to build constraints
	IgnoredOtherFiles []string // non-.go source files ignored due to build constraints
	CFiles            []string // .c source files
	CXXFiles          []string // .cc, .cxx and .cpp source files
	MFiles            []string // .m source files
	HFiles            []string // .h, .hh, .hpp and .hxx source files
	FFiles            []string // .f, .F, .for and .f90 Fortran source files
	SFiles            []string // .s source files
	SwigFiles         []string // .swig files
	SwigCXXFiles      []string // .swigcxx files
	SysoFiles         []string // .syso object files to add to archive
	TestGoFiles       []string // _test.go files in package
	XTestGoFiles      []string // _test.go files outside package

	// Embedded files
	EmbedPatterns      []string // //go:embed patterns
	EmbedFiles         []string // files matched by EmbedPatterns
	TestEmbedPatterns  []string // //go:embed patterns in TestGoFiles
	TestEmbedFiles     []string // files matched by TestEmbedPatterns
	XTestEmbedPatterns []string // //go:embed patterns in XTestGoFiles
	XTestEmbedFiles    []string // files matched by XTestEmbedPatterns

	// Cgo directives
	CgoCFLAGS    []string // cgo: flags for C compiler
	CgoCPPFLAGS  []string // cgo: flags for C preprocessor
	CgoCXXFLAGS  []string // cgo: flags for C++ compiler
	CgoFFLAGS    []string // cgo: flags for Fortran compiler
	CgoLDFLAGS   []string // cgo: flags for linker
	CgoPkgConfig []string // cgo: pkg-config names

	// Dependency information
	Imports      []string          // import paths used by this package
	ImportMap    map[string]string // map from source import to ImportPath (identity entries omitted)
	Deps         []string          // all (recursively) imported dependencies
	TestImports  []string          // imports from TestGoFiles
	XTestImports []string          // imports from XTestGoFiles

	// Error information
	Incomplete bool // this package or a dependency has an error
}
