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
	"github.com/VirusTotal/vt-cli/utils"
	"github.com/spf13/cobra"
)

var groupCmdHelp = `Get information about a group.`

var groupCmdExample = `  vt group mygroup`

// NewGroupCmd returns a new instance of the 'group' command.
func NewGroupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "group [groupname]...",
		Short:   "Get information about VirusTotal groups",
		Long:    groupCmdHelp,
		Example: groupCmdExample,
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.GetAndPrintObjects(
				"groups/%s",
				utils.StringReaderFromCmdArgs(args),
				nil)
		},
	}

	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())
	addThreadsFlag(cmd.Flags())

	cmd.AddCommand(NewPrivilegeCmd("group"))

	return cmd
}
