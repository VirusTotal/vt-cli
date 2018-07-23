// Copyright © 2017 The VirusTotal CLI authors. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"regexp"

	"github.com/spf13/cobra"
)

var analysisCmdHelp = `Get a file or URL analysis.

This command receives one or more analysis identifiers and returns information
about the analysis. The data is returned in the same order as the identifiers
appear in the command line.

If the identifiers are not provided in the command line they will be read from
the standard input, one per line.`

var analysisCmdExample = `  vt analysis 8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d8
  vt analysis 76cdb2bad9582d23c1f6f4d868218d6c
  vt analysis 76cdb2bad9582d23c1f6f4d868218d6c 44d88612fea8a8f36de82e1278abb02f
  cat list_of_analysis_ids | vt analysis`

// NewAnalysisCmd returns a new instance of the 'analysis' command.
func NewAnalysisCmd() *cobra.Command {
	cmd := &cobra.Command{
		Aliases: []string{"an"},
		Use:     "analysis [hash]...",
		Short:   "Get a file or URL analysis",
		Long:    analysisCmdHelp,
		Example: analysisCmdExample,

		RunE: func(cmd *cobra.Command, args []string) error {
			re, _ := regexp.Compile(`(f|u)-[[:xdigit:]]{64}-\d+|[\d\w=]{20,}`)
			p, err := NewObjectPrinter(cmd)
			if err != nil {
				return err
			}
			return p.Print("analyses", args, re)
		},
	}

	addThreadsFlag(cmd.Flags())
	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())

	return cmd
}
