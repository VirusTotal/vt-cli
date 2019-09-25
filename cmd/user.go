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
	"strings"

	"github.com/spf13/cobra"
)

var userCmdHelp = `Get information about a VirusTotal user.`

var userCmdExample = `  vt user joe
  vt user 1ebb658141155c16d8bf89629379098b4cf31d4613b13784a108c6a4805c963b
  vt user joe@domain.com`

// NewUserCmd returns a new instance of the 'user' command.
func NewUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "user [username | apikey | email]...",
		Short:   "Get information about VirusTotal users",
		Long:    userCmdHelp,
		Example: userCmdExample,
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.GetAndPrintObjects(
				"users/%s?relationships="+strings.Join([]string{
					"groups",
					"api_quota_group",
					"intelligence_quota_group",
					"monitor_quota_group",
				}, ","), args, nil)

		},
	}

	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())
	addThreadsFlag(cmd.Flags())

	return cmd
}
