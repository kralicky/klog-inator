package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/kralicky/klog-inator/pkg/inator"
	"github.com/spf13/cobra"
)

// searchCmd represents the search command
var searchCmd = &cobra.Command{
	Use:   "search [pattern]",
	Args:  cobra.ExactArgs(1),
	Short: "Search through packages for log statements",
	Run: func(cmd *cobra.Command, args []string) {
		list := exec.Command("go", "list", "-json", args[0])
		output := new(bytes.Buffer)
		list.Stdout = output
		if err := list.Run(); err != nil {
			log.Fatal(err)
		}

		// cant figure out how to do this in code lol
		// the json decoder is way too slow
		minified := new(bytes.Buffer)
		jq := exec.Command("jq", "-c")
		jq.Stdin = output
		jq.Stdout = minified
		if err := jq.Run(); err != nil {
			log.Fatal("jq error: " + err.Error())
		}
		objects := strings.Split(minified.String(), "\n")
		if objects[len(objects)-1] == "" {
			objects = objects[:len(objects)-1]
		}
		statements := inator.Search(objects)
		printJson, _ := cmd.Flags().GetBool("json")
		if printJson {
			statementSlice := []*inator.LogStatement{}
			for statement := range statements {
				statementSlice = append(statementSlice, statement)
			}
			data, _ := json.Marshal(statementSlice)
			fmt.Println(string(data))
		} else {
			for statement := range statements {
				var severity, verbosity string
				switch statement.Severity {
				case 0:
					severity = "INFO"
				case 1:
					severity = "WARNING"
				case 2:
					severity = "ERROR"
				case 3:
					severity = "FATAL"
				default:
					severity = "UNKNOWN"
				}

				if statement.Verbosity == nil {
					verbosity = "N/A"
				} else {
					verbosity = fmt.Sprint(*statement.Verbosity)
				}

				fmt.Printf("%s:%d %s %s %s\n",
					statement.SourceFile, statement.LineNumber,
					severity, verbosity, statement.FormatString)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(searchCmd)

	searchCmd.Flags().Bool("json", false, "Print results in json format")
}
