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
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var bashCompletionGenerators = map[string]func(out io.Writer, cmd *cobra.Command) error{
	"bash": func(out io.Writer, cmd *cobra.Command) error {
		return cmd.GenBashCompletion(out)
	},
	"zsh": func(out io.Writer, cmd *cobra.Command) error {
		return cmd.GenZshCompletion(out)
	},
	"fish": func(out io.Writer, cmd *cobra.Command) error {
		return cmd.GenFishCompletion(out, true)
	},
}

var completionCmdHelp = `Output shell completion code for the specified shell (bash or zsh).

The shell code must be evaluated to provide interactive completion of vt commands.  This can be done by sourcing it from
the .bash_profile.

Note for zsh users: [1] zsh completions are only supported in versions of zsh >= 5.2`

// NewCompletionCmd returns command 'completion'
func NewCompletionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion <shell>",
		Short: "Output shell completion code for the specified shell (bash or zsh)",
		Long:  completionCmdHelp,
		Args:  cobra.ExactArgs(1),

		PreRunE: func(cmd *cobra.Command, args []string) error {
			_, found := bashCompletionGenerators[args[0]]
			if !found {
				return fmt.Errorf("Unsupported shell type %q", args[0])
			}
			return nil
		},

		Run: func(cmd *cobra.Command, args []string) {
			run, _ := bashCompletionGenerators[args[0]]
			run(os.Stdout, cmd.Parent())
		},
	}

	cmd.MarkZshCompPositionalArgumentWords(1, "bash", "zsh")

	return cmd
}
