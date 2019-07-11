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
	"fmt"
	"strings"

	vt "github.com/VirusTotal/vt-go"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var userCmdHelp = `Get information about a VirusTotal user.`

var userCmdExample = `  vt user joe
  vt user joe@domain.com`

func printUserHumanFriendly(u *vt.Object) error {

	fn, _ := u.GetString("first_name")
	ln, _ := u.GetString("last_name")

	if fn != "" || ln != "" {
		fmt.Printf("name       : %s\n", strings.Join([]string{fn, ln}, " "))
	}

	fmt.Printf("username   : %s\n", u.ID)
	fmt.Printf("email      : %s\n", u.MustGetString("email"))
	fmt.Printf("apikey     : %s\n", u.MustGetString("apikey"))
	fmt.Printf("status     : %s\n", u.MustGetString("status"))
	fmt.Printf("user since : %s\n", u.MustGetTime("user_since"))
	fmt.Printf("last login : %s\n", u.MustGetTime("last_login"))
	fmt.Printf("2fa        : %v\n", u.MustGetBool("has_2fa"))

	return nil
}

// NewUserCmd returns a new instance of the 'user' command.
func NewUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "user [username]",
		Short:   "Get information about a VirusTotal user",
		Long:    userCmdHelp,
		Example: userCmdExample,
		Args:    cobra.ExactArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			user, err := client.GetObject(
				vt.URL("users/%s?relationships=%s",
					args[0],
					strings.Join([]string{
						"groups",
						"api_quota_group",
						"intelligence_quota_group",
						"monitor_quota_group",
					}, ",")))
			if err != nil {
				return err
			}
			if viper.GetBool("human") {
				for _, flag := range []string{"include", "exclude"} {
					if cmd.Flag(flag).Changed {
						return fmt.Errorf("--%s can't be used with --human", flag)
					}
				}
				return printUserHumanFriendly(user)
			}
			p, err := NewObjectPrinter(cmd)
			if err != nil {
				return err
			}
			return p.PrintObject(user)
		},
	}

	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())
	addHumanFlag(cmd.Flags())

	return cmd
}
