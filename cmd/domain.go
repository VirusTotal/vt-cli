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
	"github.com/spf13/cobra"
)

var domainCmdHelp = `Get information about one or more Internet domains.

This command receives one or more Internet domains and returns information about
them. The data is returned in the same order as the domains appear in the
command line.

If the domains are not provided in the command line they will be read from
the standard input, one per line.`

var domainCmdExample = `  vt domain virustotal.com
  vt domain virustotal.com google.com
  cat list_of_domains | vt domain -`

// NewDomainCmd returns a new instance of the 'domain' command.
func NewDomainCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:     "domain [domain]...",
		Short:   "Get information about Internet domains",
		Long:    domainCmdHelp,
		Example: domainCmdExample,
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			p.GetAndPrintObjects("domains", args, nil)
			return nil
		},
	}

	addRelationshipCmds(cmd, "domains", "domain", "[domain]")

	addThreadsFlag(cmd.Flags())
	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())

	return cmd
}
