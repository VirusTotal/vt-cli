// Copyright © 2019 The VirusTotal CLI authors. All Rights Reserved.
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

var userCmdHelp = `Get a user.

This command receives one or more analysis identifiers and returns information
about the analysis. The data is returned in the same order as the identifiers
appear in the command line.

If the identifiers are not provided in the command line they will be read from
the standard input, one per line.`

var userCmdExample = `  vt user joe
  vt user joe@domain.com
  cat list_of_usernames | vt user -`

// NewUserCmd returns a new instance of the 'user' command.
func NewUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "user [username]...",
		Short:   "Get a VirusTotal user",
		Long:    userCmdHelp,
		Example: userCmdExample,
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			re, _ := regexp.Compile(`[\w\.\-%@\+]+`)
			p, err := NewObjectPrinter(cmd)
			if err != nil {
				return err
			}
			return p.Print("users", args, re)
		},
	}

	addThreadsFlag(cmd.Flags())
	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())

	return cmd
}
