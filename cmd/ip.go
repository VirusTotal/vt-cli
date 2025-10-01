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
)

var ipCmdHelp = `Get information about one or more IP addresses.

This command receives one or more IP addresses and returns information about
them. The information for each IP address is returned in the same order as the
IP addresses are passed to the command.

If the command receives a single hypen (-) the IP addresses will be read from
the standard input, one per line.`

var ipCmdExample = `  vt ip 8.8.8.8
  vt ip 8.8.8.8 8.8.4.4
  cat list_of_ips | vt ip -`

// NewIPCmd returns a new instance of the 'ip' command.
func NewIPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ip [ip]...",
		Short:   "Get information about IP addresses",
		Long:    ipCmdHelp,
		Example: ipCmdExample,
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			re, _ := regexp.Compile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.GetAndPrintObjects(
				"ip_addresses/%s",
				utils.StringReaderFromCmdArgs(args),
				re)
		},
	}

	addRelationshipCmds(cmd, "ip_addresses", "ip_address", "[ip]", false)

	addThreadsFlag(cmd.Flags())
	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())

	return cmd
}
