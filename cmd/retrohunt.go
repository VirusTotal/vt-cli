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
	"io/ioutil"
	"os"
	"regexp"

	"github.com/VirusTotal/vt-cli/utils"
	"github.com/VirusTotal/vt-cli/yaml"
	"github.com/VirusTotal/vt-go/vt"
	"github.com/spf13/cobra"
)

// NewRetrohuntListCmd returns a new instance of the 'list' command.
func NewRetrohuntListCmd() *cobra.Command {

	cmd := &cobra.Command{
		Aliases: []string{"ls"},
		Use:     "list",
		Short:   "List retrohunt jobs",
		Long:    `List retrohunt jobs.`,

		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewObjectPrinter()
			if err != nil {
				return err
			}
			return p.PrintCollection(vt.URL("intelligence/retrohunt_jobs"))
		},
	}

	addIncludeExcludeFlags(cmd.Flags())
	addFilterFlag(cmd.Flags())
	addLimitFlag(cmd.Flags())
	addCursorFlag(cmd.Flags())

	return cmd
}

var retrohuntStartCmdHelp = `Start a retrohunt job.

This command receives a file containing YARA rules and starts a retrohunt job with those rules.`

// NewRetrohuntStartCmd returns a new instance of the 'start' command.
func NewRetrohuntStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start [file]",
		Short: "Start a retrohunt job",
		Long:  retrohuntStartCmdHelp,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			client, err := utils.NewAPIClient()
			if err != nil {
				return err
			}
			p, err := NewObjectPrinter()
			if err != nil {
				return err
			}

			obj := vt.NewObject()
			obj.Type = "retrohunt_job"

			var rules []byte
			if args[0] == "-" {
				rules, err = ioutil.ReadAll(os.Stdin)
			} else {
				rules, err = ioutil.ReadFile(args[0])
			}
			if err != nil {
				return err
			}

			obj.Attributes["rules"] = string(rules)

			err = client.CreateObject(vt.URL("intelligence/retrohunt_jobs"), obj)
			if err != nil {
				return err
			}
			return p.PrintObject(obj)
		},
	}
}

// NewRetrohuntAbortCmd returns a new instance of the 'abort' command.
func NewRetrohuntAbortCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "abort [job id]",
		Short: "Abort a retrohunt job",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := utils.NewAPIClient()
			if err != nil {
				return err
			}
			url := vt.URL("intelligence/retrohunt_jobs/%s/abort", args[0])
			_, err = client.Post(url, nil)
			return err
		},
	}
}

// NewRetrohuntDeleteCmd returns a new instance of the 'delete' command.
func NewRetrohuntDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Aliases: []string{"del", "rm"},
		Use:     "delete [job id]",
		Short:   "Delete a retrohunt job",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := utils.NewAPIClient()
			if err != nil {
				return err
			}
			url := vt.URL("intelligence/retrohunt_jobs/%s", args[0])
			_, err = client.Delete(url)
			return err
		},
	}
}

// NewRetrohuntMatchesCmd returns a new instance of the 'matches' command.
func NewRetrohuntMatchesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "matches [job id]",
		Short: "Get matches for a retrohunt job",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := utils.NewAPIClient()
			if err != nil {
				return err
			}
			matches := make([]map[string]interface{}, 0)
			url := vt.URL("intelligence/retrohunt_jobs/%s/matches", args[0])
			client.GetData(url, &matches)
			return yaml.NewColorEncoder(os.Stdout, colorScheme).Encode(matches)
		},
	}
}

// NewRetrohuntCmd returns a new instance of the 'retrohunt' command.
func NewRetrohuntCmd() *cobra.Command {

	cmd := &cobra.Command{
		Aliases: []string{"rh"},
		Use:     "retrohunt [id]...",
		Short:   "Manage retrohunt jobs",
		Long:    `Manage retrohunt jobs.`,
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			re, _ := regexp.Compile("\\w+-\\d+")
			p, err := NewObjectPrinter()
			if err != nil {
				return err
			}
			return p.Print("intelligence/retrohunt_jobs", args, re)
		},
	}

	addThreadsFlag(cmd.Flags())

	cmd.AddCommand(NewRetrohuntAbortCmd())
	cmd.AddCommand(NewRetrohuntDeleteCmd())
	cmd.AddCommand(NewRetrohuntListCmd())
	cmd.AddCommand(NewRetrohuntMatchesCmd())
	cmd.AddCommand(NewRetrohuntStartCmd())

	return cmd
}
