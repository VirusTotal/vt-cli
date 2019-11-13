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
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"sync"

	vt "github.com/VirusTotal/vt-go"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var notificationsDeleteCmdHelp = `Delete hunting notifications.

This command deletes the malware hunting notifications associated to the
currently configured API key.`

// NewHuntingNotificationDeleteCmd returns a command for deleting all hunting
// notifications for the current user.
func NewHuntingNotificationDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete [notification id]...",
		Short: "Delete hunting notifications",
		Long:  notificationsDeleteCmdHelp,
		RunE: func(cmd *cobra.Command, args []string) error {
			deleteAll := viper.GetBool("all")
			deleteTag := viper.GetString("with-tag")
			if len(args) == 0 && !deleteAll && deleteTag == "" {
				return errors.New("Specify notification id or use --all or --with-tag")
			}
			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			if deleteAll {
				_, err = client.Delete(vt.URL("intelligence/hunting_notifications"))
			} else if deleteTag != "" {
				_, err = client.Delete(vt.URL("intelligence/hunting_notifications?tag=%s", deleteTag))
			} else {
				var wg sync.WaitGroup
				for _, arg := range args {
					wg.Add(1)
					go func(notificationID string) {
						url := vt.URL("intelligence/hunting_notifications/%s", notificationID)
						if _, err := client.Delete(url); err != nil {
							fmt.Fprintf(os.Stderr, "%v\n", err)
						}
						wg.Done()
					}(arg)
				}
				wg.Wait()
			}
			return err
		},
	}

	cmd.Flags().BoolP("all", "a", false, "delete all notifications")
	cmd.Flags().StringP("with-tag", "t", "", "delete notifications with a given tag")

	return cmd
}

var notificationsListCmdHelp = `List malware hunting notifications.

This command list the malware hunting notifications associated to the currently
configured API key.`

// NewHuntingNotificationListCmd returns a new instance of the 'notifications list' command.
func NewHuntingNotificationListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Aliases: []string{"ls"},
		Use:     "list",
		Short:   "List notifications",
		Long:    notificationsListCmdHelp,

		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewPrinter(cmd)
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

	cmd.AddCommand(NewHuntingNotificationDeleteCmd())

	return cmd
}

// NewHuntingNotificationCmd returns a new instance of the 'notifications' command.
func NewHuntingNotificationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Aliases: []string{"nt"},
		Use:     "notification [id]...",
		Short:   "Manage malware hunting notifications",
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			re, _ := regexp.Compile("\\d+")
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.GetAndPrintObjects("intelligence/hunting_notifications/%s", args, re)
		},
	}

	addThreadsFlag(cmd.Flags())

	cmd.AddCommand(NewHuntingNotificationListCmd())
	cmd.AddCommand(NewHuntingNotificationDeleteCmd())

	return cmd
}

var rulesetsListCmdHelp = `List malware hunting rulesets.

This command list the malware hunting rulesets associated to the currently
configured API key.`

// NewHuntingRulesetListCmd returns a new instance of the 'rulesets list' command.
func NewHuntingRulesetListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Aliases: []string{"ls"},
		Use:     "list",
		Short:   "List rulesets",
		Long:    rulesetsListCmdHelp,

		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.PrintCollection(vt.URL("intelligence/hunting_rulesets?relationships=owner,editors"))
		},
	}

	addIncludeExcludeFlags(cmd.Flags())
	addFilterFlag(cmd.Flags())
	addLimitFlag(cmd.Flags())
	addCursorFlag(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())

	return cmd
}

func patchRuleset(id, attr string, value interface{}) error {
	client, err := NewAPIClient()
	if err != nil {
		return err
	}
	obj := vt.NewObjectWithID("hunting_ruleset", id)
	obj.Set(attr, value)
	return client.PatchObject(vt.URL("intelligence/hunting_rulesets/%s", id), obj)
}

// NewHuntingRulesetDisableCmd returns a command for disabling a given ruleset.
func NewHuntingRulesetDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable [ruleset id]",
		Short: "Disable ruleset",
		Args:  cobra.ExactArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			return patchRuleset(args[0], "enabled", false)
		},
	}
}

// NewHuntingRulesetEnableCmd returns a command for enabling a given ruleset.
func NewHuntingRulesetEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable [ruleset id]",
		Short: "Enable ruleset",
		Args:  cobra.ExactArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			return patchRuleset(args[0], "enabled", true)
		},
	}
}

// NewHuntingRulesetRenameCmd returns a command for renaming a given ruleset.
func NewHuntingRulesetRenameCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rename [ruleset id] [name]",
		Short: "Rename ruleset",
		Args:  cobra.ExactArgs(2),

		RunE: func(cmd *cobra.Command, args []string) error {
			return patchRuleset(args[0], "name", args[1])
		},
	}
}

// NewHuntingRulesetSetLimitCmd returns a command for changing a ruleset's limit.
func NewHuntingRulesetSetLimitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "setlimit [ruleset id] [limit]",
		Short: "Set ruleset limit",
		Args:  cobra.MinimumNArgs(2),

		RunE: func(cmd *cobra.Command, args []string) error {
			limit, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("invalid limit: %s", args[1])
			}
			return patchRuleset(args[0], "limit", limit)
		},
	}
}

// NewHuntingRulesetUpdateCmd returns a command for updating ruleset's rules.
func NewHuntingRulesetUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update [ruleset id] [rules file]",
		Short: "Change the rules for a ruleset.",
		Args:  cobra.MinimumNArgs(2),

		RunE: func(cmd *cobra.Command, args []string) error {
			rules, err := ReadFile(args[1])
			if err != nil {
				return err
			}
			return patchRuleset(args[0], "rules", string(rules))
		},
	}
}

// NewHuntingRulesetDeleteCmd returns a command for deleting a given ruleset.
func NewHuntingRulesetDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Aliases: []string{"del", "rm"},
		Use:     "delete [ruleset id]...",
		Short:   "Delete rulesets",

		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			deleteAll := viper.GetBool("all")
			if len(args) == 0 && !deleteAll {
				return errors.New("Specify ruleset id or use --all")
			}
			if deleteAll {
				fmt.Print("Enter your VirusTotal username to confirm: ")
				scanner := bufio.NewScanner(os.Stdin)
				scanner.Scan()
				username := scanner.Text()
				_, err = client.Delete(
					vt.URL("intelligence/hunting_rulesets"),
					vt.WithHeader("x-confirm-delete", username))
			} else {
				var wg sync.WaitGroup
				for _, arg := range args {
					wg.Add(1)
					go func(rulesetID string) {
						url := vt.URL("intelligence/hunting_rulesets/%s", rulesetID)
						if _, err := client.Delete(url); err != nil {
							fmt.Fprintf(os.Stderr, "%v\n", err)
						}
						wg.Done()
					}(arg)
				}
				wg.Wait()
			}
			return err
		},
	}

	cmd.Flags().BoolP("all", "a", false, "delete all rulesets")

	return cmd
}

// NewHuntingRulesetAddCmd returns a command for adding a new ruleset.
func NewHuntingRulesetAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add [ruleset name] [rules file]",
		Short: "Add a new ruleset",
		Args:  cobra.ExactArgs(2),

		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			rules, err := ReadFile(args[1])
			if err != nil {
				return err
			}
			obj := vt.NewObject("hunting_ruleset")
			obj.SetString("name", args[0])
			obj.SetString("rules", string(rules))

			err = client.PostObject(vt.URL("intelligence/hunting_rulesets"), obj)
			if err != nil {
				return err
			}
			return p.PrintObject(obj)
		},
	}
}

// NewHuntingRulesetCmd returns a new instance of the 'rulesets' command.
func NewHuntingRulesetCmd() *cobra.Command {

	cmd := &cobra.Command{
		Aliases: []string{"rs"},
		Use:     "ruleset [id]...",
		Short:   "Manage hunting rulesets",
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			re, _ := regexp.Compile("\\d+")
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.GetAndPrintObjects("intelligence/hunting_rulesets/%s?relationships=owner,editors", args, re)
		},
	}

	cmd.AddCommand(NewHuntingRulesetAddCmd())
	cmd.AddCommand(NewHuntingRulesetDeleteCmd())
	cmd.AddCommand(NewHuntingRulesetDisableCmd())
	cmd.AddCommand(NewHuntingRulesetEnableCmd())
	cmd.AddCommand(NewHuntingRulesetListCmd())
	cmd.AddCommand(NewHuntingRulesetRenameCmd())
	cmd.AddCommand(NewHuntingRulesetSetLimitCmd())
	cmd.AddCommand(NewHuntingRulesetUpdateCmd())

	return cmd
}

// NewHuntingCmd returns a new instance of the 'hunting' command.
func NewHuntingCmd() *cobra.Command {

	cmd := &cobra.Command{
		Aliases: []string{"ht"},
		Use:     "hunting",
		Short:   "Manage malware hunting rules and notifications",
	}

	cmd.AddCommand(NewHuntingNotificationCmd())
	cmd.AddCommand(NewHuntingRulesetCmd())

	return cmd
}
