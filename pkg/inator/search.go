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
	"strings"
	"sync"
)

type SearchList []*LogStatement
type SearchMap map[string]*LogStatement

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

func LoadSearchList(filename string) (SearchList, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var list []*LogStatement
	dec := json.NewDecoder(f)
	if err := dec.Decode(&list); err != nil {
		return nil, err
	}
	return list, nil
}

func (s SearchList) GenerateSearchMap() (sm SearchMap, collisions map[string][]*LogStatement) {
	collisions = make(map[string][]*LogStatement)
	sm = SearchMap{}
	for _, stmt := range s {
		fp := stmt.Fingerprint()
		if existing, ok := sm[fp]; !ok {
			sm[fp] = stmt
		} else {
			if _, ok := collisions[fp]; !ok {
				collisions[fp] = []*LogStatement{existing}
			}
			collisions[fp] = append(collisions[fp], stmt)
		}
	}
	return
}

func resolveSeverity(
	message string,
	severity Severity,
	errorKeywords []string,
) (newSeverity Severity) {
	if severity != SeverityInfo {
		return severity
	}
	defer func() {
		if newSeverity == SeverityError {
			fmt.Fprintf(os.Stderr, "Treating info message as error: %s\n", message)
		}
	}()
	unquoted := strings.ToLower(strings.Trim(message, ` "`))
	for _, keyword := range errorKeywords {
		if keyword[0] == '^' {
			if strings.HasPrefix(unquoted, strings.ToLower(keyword[1:])) {
				return SeverityError
			}
		} else if keyword[len(keyword)-1] == '$' {
			if strings.HasSuffix(unquoted, strings.ToLower(keyword[:len(keyword)-1])) {
				return SeverityError
			}
		} else {
			if strings.Contains(unquoted, strings.ToLower(keyword)) {
				return SeverityError
			}
		}
	}
	return SeverityInfo
}

func Search(
	jsonObjects []string,
	excludeModules []string,
	excludeFilenames []string,
	errorKeywords []string,
) <-chan *LogStatement {
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
			for _, exclude := range excludeModules {
				if strings.Contains(pkg.ImportPath, exclude) {
					fmt.Fprintf(os.Stderr, "Excluding package %s\n", pkg.ImportPath)
					return
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

	for _, pkgWithLog := range packagesWithLog {
		go func(pkgWithLog *internalPackage) {
			defer wg.Done()
			fileset := token.NewFileSet()
			for _, file := range pkgWithLog.GoFiles {
				for _, exclude := range excludeFilenames {
					if strings.Contains(file, exclude) {
						fmt.Fprintf(os.Stderr, "Excluding file %s\n", file)
						return
					}
				}
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
								SourceFile: relPath,
								LineNumber: fileset.Position(call.Pos()).Line,
								Severity: resolveSeverity(
									stringLiteralFmtArg,
									Severity(meta.Severity),
									errorKeywords,
								),
								FormatString: stringLiteralFmtArg,
							}
							logStatements <- &stmt
							return false
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
								SourceFile: relPath,
								LineNumber: fileset.Position(call.Pos()).Line,
								Severity: resolveSeverity(
									stringLiteralFmtArg,
									Severity(meta.Severity),
									errorKeywords,
								),
								Verbosity:    verbosity,
								FormatString: stringLiteralFmtArg,
							}
							logStatements <- &stmt
							return false
						}
						return true
					})
				}
			}
		}(pkgWithLog)
	}
	go func() {
		wg.Wait()
		close(logStatements)
	}()
	return logStatements
}
