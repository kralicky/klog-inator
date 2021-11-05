package inator

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

type klogFunctionMeta struct {
	Severity        int32
	FormatStringPos int
	MinArgs         int
}

var severityMap = map[string]klogFunctionMeta{
	"Info":         {Severity: 0, FormatStringPos: 0},
	"InfoDepth":    {Severity: 0, FormatStringPos: 1, MinArgs: 1},
	"Infoln":       {Severity: 0, FormatStringPos: 0},
	"Infof":        {Severity: 0, FormatStringPos: 0, MinArgs: 1},
	"InfoS":        {Severity: 0, FormatStringPos: 0, MinArgs: 1},
	"InfoSDepth":   {Severity: 0, FormatStringPos: 1, MinArgs: 2},
	"Warning":      {Severity: 1, FormatStringPos: 0},
	"WarningDepth": {Severity: 1, FormatStringPos: 1, MinArgs: 1},
	"Warningln":    {Severity: 1, FormatStringPos: 0},
	"Warningf":     {Severity: 1, FormatStringPos: 0, MinArgs: 1},
	"Error":        {Severity: 2, FormatStringPos: 0},
	"ErrorDepth":   {Severity: 2, FormatStringPos: 1, MinArgs: 1},
	"Errorln":      {Severity: 2, FormatStringPos: 0},
	"Errorf":       {Severity: 2, FormatStringPos: 0, MinArgs: 1},
	"ErrorS":       {Severity: 2, FormatStringPos: 1, MinArgs: 2},
	"ErrorSDepth":  {Severity: 2, FormatStringPos: 2, MinArgs: 3},
	"Fatal":        {Severity: 3, FormatStringPos: 0},
	"FatalDepth":   {Severity: 3, FormatStringPos: 1, MinArgs: 1},
	"Fatalln":      {Severity: 3, FormatStringPos: 0},
	"Fatalf":       {Severity: 3, FormatStringPos: 0, MinArgs: 1},
	"Exit":         {Severity: 3, FormatStringPos: 0},
	"ExitDepth":    {Severity: 3, FormatStringPos: 1, MinArgs: 1},
	"Exitln":       {Severity: 3, FormatStringPos: 0},
	"Exitf":        {Severity: 3, FormatStringPos: 0, MinArgs: 1},
}

func Search(jsonObjects []string) <-chan *LogStatement {
	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(len(jsonObjects))
	searchPackages := make([]*internalPackage, len(jsonObjects))
	for i, doc := range jsonObjects {
		go func(i int, doc string) {
			defer wg.Done()
			pkg := &internalPackage{}
			if err := json.Unmarshal([]byte(doc), &pkg); err != nil {
				fmt.Println(doc)
				log.Fatal("error parsing json: " + err.Error())
			}
			klogFound := false
			for _, im := range pkg.Imports {
				if im == "k8s.io/klog/v2" {
					klogFound = true
				}
			}
			if klogFound {
				searchPackages[i] = pkg
			}
		}(i, doc)
	}
	wg.Wait()

	// remove nil entries from searchPackages
	packagesWithLog := make([]*internalPackage, 0, len(searchPackages))
	for _, pkg := range searchPackages {
		if pkg != nil {
			packagesWithLog = append(packagesWithLog, pkg)
		}
	}

	wg = sync.WaitGroup{}
	wg.Add(len(packagesWithLog))
	logStatements := make(chan *LogStatement, len(packagesWithLog))

	for i, pkgWithLog := range packagesWithLog {
		go func(i int, pkgWithLog *internalPackage) {
			defer wg.Done()
			fileset := token.NewFileSet()
			for _, file := range pkgWithLog.GoFiles {
				f, err := parser.ParseFile(fileset, filepath.Join(pkgWithLog.Dir, file), nil, parser.ParseComments)
				if err != nil {
					log.Fatal("error parsing file: " + err.Error())
				}
				// find klog import
				klogPackageName := "klog"
				for _, im := range f.Imports {
					if im.Path.Value == `"k8s.io/klog/v2"` {
						// get klog package name
						if name := im.Name.String(); name != "<nil>" && name != "" && name != "." {
							klogPackageName = im.Name.Name
						}
					}
				}
				if klogPackageName == "" {
					panic("bug")
				}
				fileName := file
				relPath, err := filepath.Rel(wd, filepath.Join(pkgWithLog.Dir, fileName))
				if err != nil {
					log.Fatal(err)
				}
				for _, decl := range f.Decls {
					fn, ok := decl.(*ast.FuncDecl)
					if !ok {
						continue
					}
					// find any calls to klog.v2
					ast.Inspect(fn.Body, func(n ast.Node) bool {
						call, ok := n.(*ast.CallExpr)
						if !ok {
							return true
						}
						fun, ok := call.Fun.(*ast.SelectorExpr)
						if !ok {
							return true
						}
						// Check if the function name matches one of the klog functions
						var meta klogFunctionMeta
						if m, ok := severityMap[fun.Sel.Name]; ok {
							meta = m
						} else {
							return true
						}

						// At this point we do not yet know for sure if this is a klog call

						// Try to match one of the two possible formats:
						// 1. klog.FunctionName(...)
						// 2. klog.V(...).FunctionName(...)
						//
						// Below, X is either an Ident or CallExpr, respectively:
						// 1. klog.FunctionName(...)
						//    ^^^^
						// 2. klog.V(...).FunctionName(...)
						//    ^^^^^^^^^^^
						if len(call.Args) < meta.MinArgs {
							return true
						}

						var stringLiteralFmtArg string
						// In both cases, the arg to FunctionName (as shown above) must
						// either be a BasicLit of kind STRING, or an Ident.

						if len(call.Args) > meta.FormatStringPos {
							switch arg := call.Args[meta.FormatStringPos].(type) {
							case *ast.BasicLit:
								if arg.Kind != token.STRING {
									return true
								}
								stringLiteralFmtArg = arg.Value
							case *ast.Ident:
							default:
								return true
							}
						}

						switch ex := fun.X.(type) {
						case *ast.Ident:
							// In this case, the following must be true of the Ident:
							// 1. It has X of type Ident with Name == klog

							if ex.Name != klogPackageName {
								return true
							}

							// This is a klog call of form 1
							stmt := LogStatement{
								SourceFile:   relPath,
								LineNumber:   fileset.Position(call.Pos()).Line,
								Severity:     meta.Severity,
								FormatString: stringLiteralFmtArg,
							}
							logStatements <- &stmt
							return true
						case *ast.CallExpr:
							// In this case, the following must be true of the CallExpr:
							// 1. It has len(Args)==1 and Args[0] is a BasicLit containing an INT value
							// 2. It has Fun of type SelectorExpr which has:
							//    - Sel of type Ident with Name == V
							//    - X of type Ident with Name == klog

							if len(ex.Args) != 1 {
								return true
							}
							lit, ok := ex.Args[0].(*ast.BasicLit)
							if !ok {
								return true
							}
							if lit.Kind != token.INT {
								return true
							}
							var verbosity *int
							v, err := strconv.Atoi(lit.Value)
							if err == nil {
								verbosity = &v
							}
							// Check the V function name
							vFunc, ok := ex.Fun.(*ast.SelectorExpr)
							if !ok {
								return true
							}
							if vFunc.Sel.Name != "V" {
								return true
							}
							// Check the klog package name
							ident, ok := vFunc.X.(*ast.Ident)
							if !ok {
								return true
							}
							if ident.Name != klogPackageName {
								return true
							}

							// This is a klog call of form 2
							stmt := LogStatement{
								SourceFile:   relPath,
								LineNumber:   fileset.Position(call.Pos()).Line,
								Severity:     meta.Severity, // in practice, this is always 0
								Verbosity:    verbosity,
								FormatString: stringLiteralFmtArg,
							}
							logStatements <- &stmt
							return true
						}
						return true
					})
				}
			}
		}(i, pkgWithLog)
	}
	go func() {
		wg.Wait()
		close(logStatements)
	}()
	return logStatements
}