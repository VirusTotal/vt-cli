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
	"os"
	"strconv"

	"github.com/VirusTotal/vt-cli/utils"
	"github.com/VirusTotal/vt-go/vt"
	"github.com/spf13/cobra"
)

var notificationsPurgeCmdHelp = `Delete all hunting notifications.

This command deletes all the malware hunting notifications associated to the
currently configured API key.`

// NewHuntingNotificationsPurgeCmd returns a command for deleting all hunting
// notifications for the current user.
func NewHuntingNotificationsPurgeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "purge",
		Short: "Delete all hunting notifications",
		Long:  notificationsPurgeCmdHelp,

		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := utils.NewAPIClient()
			if err != nil {
				return err
			}
			_, err = client.Delete(vt.URL("intelligence/hunting_notifications"))
			return err
		},
	}

	return cmd
}

var notificationsListCmdHelp = `List malware hunting notifications.

This command list the malware hunting notifications associated to the currently
configured API key.`

// NewHuntingNotificationsListCmd returns a new instance of the 'notifications list' command.
func NewHuntingNotificationsListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Aliases: []string{"ls"},
		Use:     "list",
		Short:   "List notifications",
		Long:    notificationsListCmdHelp,

		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewObjectPrinter()
			if err != nil {
				return err
			}
			return p.PrintCollection(vt.URL("intelligence/hunting_notifications?relationships=file"))
		},
	}

	addIncludeExcludeFlags(cmd.Flags())
	addFilterFlag(cmd.Flags())
	addLimitFlag(cmd.Flags())
	addCursorFlag(cmd.Flags())

	cmd.AddCommand(NewHuntingNotificationsPurgeCmd())

	return cmd
}

// NewHuntingNotificationsCmd returns a new instance of the 'notifications' command.
func NewHuntingNotificationsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Aliases: []string{"nt"},
		Use:     "notifications",
		Short:   "Manage malware hunting notifications",
	}

	cmd.AddCommand(NewHuntingNotificationsListCmd())
	cmd.AddCommand(NewHuntingNotificationsPurgeCmd())

	return cmd
}

var rulesetsListCmdHelp = `List malware hunting rulesets.

This command list the malware hunting rulesets associated to the currently
configured API key.`

// NewHuntingRulesetsListCmd returns a new instance of the 'rulesets list' command.
func NewHuntingRulesetsListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Aliases: []string{"ls"},
		Use:     "list",
		Short:   "List rulesets",
		Long:    rulesetsListCmdHelp,

		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewObjectPrinter()
			if err != nil {
				return err
			}
			return p.PrintCollection(vt.URL("intelligence/hunting_rulesets"))
		},
	}

	addIncludeExcludeFlags(cmd.Flags())
	addFilterFlag(cmd.Flags())
	addLimitFlag(cmd.Flags())
	addCursorFlag(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())

	return cmd
}

func patchRuleset(id string, attrs map[string]interface{}) error {
	client, err := utils.NewAPIClient()
	if err != nil {
		return err
	}
	obj := &vt.Object{
		ID:         id,
		Type:       "hunting_ruleset",
		Attributes: attrs,
	}
	return client.PatchObject(vt.URL("intelligence/hunting_rulesets/%s", id), obj)
}

// NewHuntingRulesetsDisableCmd returns a command for disabling a given ruleset.
func NewHuntingRulesetsDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable [ruleset id]",
		Short: "Disable ruleset",
		Args:  cobra.ExactArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			return patchRuleset(args[0], map[string]interface{}{
				"enabled": false,
			})
		},
	}
}

// NewHuntingRulesetsEnableCmd returns a command for enabling a given ruleset.
func NewHuntingRulesetsEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable [ruleset id]",
		Short: "Enable ruleset",
		Args:  cobra.ExactArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			return patchRuleset(args[0], map[string]interface{}{
				"enabled": true,
			})
		},
	}
}

// NewHuntingRulesetsRenameCmd returns a command for renaming a given ruleset.
func NewHuntingRulesetsRenameCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rename [ruleset id] [name]",
		Short: "Rename ruleset",
		Args:  cobra.ExactArgs(2),

		RunE: func(cmd *cobra.Command, args []string) error {
			return patchRuleset(args[0], map[string]interface{}{
				"name": args[1],
			})
		},
	}
}

// NewHuntingRulesetsSetLimitCmd returns a command for changing a ruleset's limit.
func NewHuntingRulesetsSetLimitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "setlimit [ruleset id] [limit]",
		Short: "Set ruleset limit",
		Args:  cobra.MinimumNArgs(2),

		RunE: func(cmd *cobra.Command, args []string) error {
			limit, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("invalid limit: %s", args[1])
			}
			return patchRuleset(args[0], map[string]interface{}{
				"limit": limit,
			})
		},
	}
}

// NewHuntingRulesetsDeleteCmd returns a command for deleting a given ruleset.
func NewHuntingRulesetsDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Aliases: []string{"del", "rm"},
		Use:     "delete [ruleset id]...",
		Short:   "Delete rulesets",
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := utils.NewAPIClient()
			if err != nil {
				return err
			}
			for _, arg := range args {
				url := vt.URL("intelligence/hunting_rulesets/%s", arg)
				_, err = client.Delete(url)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
			}
			return nil
		},
	}
}

// NewHuntingRulesetsAddCmd returns a command for adding a new ruleset.
func NewHuntingRulesetsAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add [ruleset name] [rules file]",
		Short: "Add a new ruleset",
		Args:  cobra.ExactArgs(2),

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
			obj.Type = "hunting_ruleset"
			rules, err := ReadFile(args[1])
			if err != nil {
				return err
			}
			obj.Attributes["name"] = args[0]
			obj.Attributes["rules"] = string(rules)
			err = client.CreateObject(vt.URL("intelligence/hunting_rulesets"), obj)
			if err != nil {
				return err
			}
			return p.PrintObject(obj)
		},
	}
}

// NewHuntingRulesetsCmd returns a new instance of the 'rulesets' command.
func NewHuntingRulesetsCmd() *cobra.Command {

	cmd := &cobra.Command{
		Aliases: []string{"rs"},
		Use:     "rulesets",
		Short:   "Get malware hunting rulesets",
	}

	cmd.AddCommand(NewHuntingRulesetsAddCmd())
	cmd.AddCommand(NewHuntingRulesetsDeleteCmd())
	cmd.AddCommand(NewHuntingRulesetsDisableCmd())
	cmd.AddCommand(NewHuntingRulesetsEnableCmd())
	cmd.AddCommand(NewHuntingRulesetsListCmd())
	cmd.AddCommand(NewHuntingRulesetsRenameCmd())
	cmd.AddCommand(NewHuntingRulesetsSetLimitCmd())

	return cmd
}

// NewHuntingCmd returns a new instance of the 'hunting' command.
func NewHuntingCmd() *cobra.Command {

	cmd := &cobra.Command{
		Aliases: []string{"ht"},
		Use:     "hunting [subcommand]",
		Short:   "Manage malware hunting rules and notifications",
	}

	cmd.AddCommand(NewHuntingNotificationsCmd())
	cmd.AddCommand(NewHuntingRulesetsCmd())

	return cmd
}
