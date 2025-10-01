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

	"github.com/VirusTotal/vt-cli/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var fileCmdHelp = `Get information about one or more files.

This command receives one or more hashes (SHA-256, SHA-1 or MD5) and returns
information about the corresponding files. The information for each file appears
in the same order as the hashes are passed to the command.

If the command receives a single hypen (-) the hashes are read from the standard
input, one per line.
`

var fileCmdExample = `  vt file 8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85
  vt file 76cdb2bad9582d23c1f6f4d868218d6c
  vt file 76cdb2bad9582d23c1f6f4d868218d6c 44d88612fea8a8f36de82e1278abb02f
  cat list_of_hashes | vt file -`

// NewFileCmd returns a new instance of the 'file' command.
func NewFileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "file [hash]...",
		Short:   "Get information about files",
		Long:    fileCmdHelp,
		Example: fileCmdExample,
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			re, _ := regexp.Compile("[[:xdigit:]]{64}|[[:xdigit:]]{40}|[[:xdigit:]]{32}")
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			if viper.GetBool("private") {
				return p.GetAndPrintObjectsWithFallback(
					[]string{"files/%s", "private/files/%s"},
					utils.StringReaderFromCmdArgs(args),
					re)
			} else {
				return p.GetAndPrintObjects(
					"files/%s",
					utils.StringReaderFromCmdArgs(args),
					re)
			}
		},
	}

	addRelationshipCmds(cmd, "files", "file", "[hash]", true)

	addThreadsFlag(cmd.Flags())
	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())
	addPrivateFlag(cmd.Flags())

	return cmd
}
