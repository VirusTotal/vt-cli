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
	"github.com/VirusTotal/vt-cli/utils"
	"regexp"

	"github.com/spf13/cobra"
)

var analysisCmdHelp = `Get a file or URL analysis.

This command receives one or more analysis identifiers and returns information
about the analysis. The data is returned in the same order as the identifiers
appear in the command line.

If the command receives a single hypen (-) the analysis identifiers are read 
from the standard input, one per line.
`

var analysisCmdExample = `  vt analysis f-e04b82f7f8afc6e599d4913bee5eb571921ec8958d1ea5e3bbffe9c7ea9a0960-1542306475
  vt analysis u-1db0ad7dbcec0676710ea0eaacd35d5e471d3e11944d53bcbd31f0cbd11bce31-1542292491
  cat list_of_analysis_ids | vt analysis -`

// NewAnalysisCmd returns a new instance of the 'analysis' command.
func NewAnalysisCmd() *cobra.Command {
	cmd := &cobra.Command{
		Aliases: []string{"an"},
		Use:     "analysis [hash]...",
		Short:   "Get a file or URL analysis",
		Long:    analysisCmdHelp,
		Example: analysisCmdExample,
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			re, _ := regexp.Compile(`(f|u)-[[:xdigit:]]{64}-\d+|[\d\w=]{20,}`)
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.GetAndPrintObjects(
				"analyses/%s",
				utils.StringReaderFromCmdArgs(args),
				re)
		},
	}

	addThreadsFlag(cmd.Flags())
	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())

	return cmd
}
