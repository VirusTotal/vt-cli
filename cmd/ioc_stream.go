// Copyright © 2023 The VirusTotal CLI authors. All Rights Reserved.
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
	"regexp"
	"strings"

	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"github.com/VirusTotal/vt-go"

	"github.com/VirusTotal/vt-cli/utils"

	"github.com/spf13/cobra"
)

var iocStreamCmdExamples = `## List:
# List notifications from a hunting rule by name
vt iocstream list -f "origin:hunting tag:my_rule"
# List notifications from a hunting ruleset by name
vt iocstream list -f "origin:hunting tag:myRuleset"
# List just the entity IDs of your IoC Stream matches
vt iocstream list -I
# List ALL the entity IDs in your IoC Stream and store them in a csv file (this might take a while)
vt iocstream list -I –limit 9999999 > results.csv
# List the first IoC Stream notifications including the hash, last_analysis_stats, size and file type
vt iocstream list -i "_id,last_analysis_stats,size,type_tag"
# Check if a hash is in your IoC Stream matches
vt iocstream list -f "entity_type:file entity_id:hash"

## Delete:
# Delete all notifications matching a filter, e.g. all matches for a YARA rule/ruleset. This process is
# asynchronous, so it can take a while to delete all the notifications.
vt iocstream delete -f "origin:hunting tag:my_rule"
# Delete a single notification with ID 1234568. The notification ID is displayed in the context_attributes.
vt iocstream delete 1234568`

var iocStreamListCmdExamples = `# List notifications from a hunting rule by name
vt iocstream list -f "origin:hunting tag:my_rule"
# List notifications from a hunting ruleset by name
vt iocstream list -f "origin:hunting tag:myRuleset"
# List just the entity IDs of your IoC Stream matches
vt iocstream list -I
# List ALL the entity IDs in your IoC Stream and store them in a csv file (this might take a while)
vt iocstream list -I –limit 9999999 > results.csv
# List the first IoC Stream notifications including the hash, last_analysis_stats, size and file type
vt iocstream list -i "_id,last_analysis_stats,size,type_tag"
# Check if a hash is in your IoC Stream matches
vt iocstream list -f "entity_type:file entity_id:hash"`

var iocStreamDeleteCmdExamples = `# Delete all notifications matching a filter, e.g. all matches for a YARA rule/ruleset
vt iocstream delete -f "origin:hunting tag:my_rule"
# Delete a single notification with ID 1234568. The notification ID is displayed in the context_attributes.
vt iocstream delete 1234568`

// NewIOCStreamCmd returns a new instance of the `ioc
func NewIOCStreamCmd() *cobra.Command {
	cmd := &cobra.Command{
		Aliases: []string{"is"},
		Use:     "iocstream [notification_id]...",
		Short:   "Manage IoC Stream notifications",
		Example: iocStreamCmdExamples,
		Args:    cobra.ExactArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			re, _ := regexp.Compile("\\d+")
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.GetAndPrintObjects(
				"ioc_stream_notifications/%s",
				utils.StringReaderFromCmdArgs(args),
				re)
		},
	}

	addThreadsFlag(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())
	addIncludeExcludeFlags(cmd.Flags())

	cmd.AddCommand(NewIOCStreamListCmd())
	cmd.AddCommand(NewIOCStreamDeleteCmd())

	return cmd
}

// NewIOCStreamListCmd returns a new instance of the `ioc_stream list` command.
func NewIOCStreamListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Aliases: []string{"il"},
		Use:     "list",
		Short:   "List IoCs from notifications",
		Example: iocStreamListCmdExamples,

		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.PrintCollection(vt.URL("ioc_stream"))
		},
	}

	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())
	addFilterFlag(cmd.Flags())
	addLimitFlag(cmd.Flags())
	addCursorFlag(cmd.Flags())

	return cmd
}

var iocStreamNotificationsDeleteCmdHelp = `Delete notifications from the IoC Stream.

The command accepts a list of IoC Stream notification IDs. If no IDs are provided,
then all the IoC Stream notifications matching the given filter are deleted.
`

// NewIOCStreamDeleteCmd returns a new instance of the `ioc_stream delete` command.
func NewIOCStreamDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "delete [notification id]...",
		Short:   "Deletes notifications from the IoC Stream",
		Long:    iocStreamNotificationsDeleteCmdHelp,
		Example: iocStreamDeleteCmdExamples,

		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			if len(args) > 0 {
				eg := &errgroup.Group{}
				for _, arg := range args {
					notificationId := arg
					eg.Go(func() error {
						targetUrl := vt.URL("ioc_stream_notifications/%s", notificationId)
						_, err := client.Delete(targetUrl)
						return err
					})
				}
				return eg.Wait()
			} else {
				filterFlag := viper.GetString("filter")
				targetUrl := vt.URL("ioc_stream")
				if strings.TrimSpace(filterFlag) == "" {
					fmt.Println("This will delete all your IoC Stream notifications.")
					fmt.Print("Confirm (y/n)? ")
					var s string
					fmt.Scanln(&s)
					if s != "y" {
						return nil
					}
				} else {
					q := targetUrl.Query()
					q.Set("filter", filterFlag)
					targetUrl.RawQuery = q.Encode()
				}
				if _, err := client.Delete(targetUrl); err != nil {
					return err
				}
				fmt.Println("Notifications being deleted. This can take a while depending on the number of notifications.")
			}
			return nil
		},
	}

	addFilterFlag(cmd.Flags())
	return cmd
}
