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

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NewVTCommand creates the `vt` command and its nested children.
func NewVTCommand() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "vt",
		Short: "A command-line tool for interacting with VirusTotal",
		Long:  `A command-line tool for interacting with VirusTotal.`,

		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := viper.BindPFlags(cmd.PersistentFlags()); err != nil {
				return err
			}
			if err := viper.BindPFlags(cmd.Flags()); err != nil {
				return err
			}
			if viper.GetBool("verbose") {
				if configFile := viper.ConfigFileUsed(); configFile != "" {
					fmt.Fprintf(os.Stderr, "* Config file: %s\n", configFile)
				}
				if apiKey := viper.GetString("apikey"); apiKey != "" {
					fmt.Fprintf(os.Stderr, "* API key: %s\n", apiKey)
				}
			}
			return nil
		},
	}

	addAPIKeyFlag(cmd.PersistentFlags())
	addVerboseFlag(cmd.PersistentFlags())

	cmd.AddCommand(NewAnalysisCmd())
	cmd.AddCommand(NewCompletionCmd())
	cmd.AddCommand(NewDomainCmd())
	cmd.AddCommand(NewDownloadCmd())
	cmd.AddCommand(NewFileCmd())
	cmd.AddCommand(NewGenDocCmd())
	cmd.AddCommand(NewHuntingCmd())
	cmd.AddCommand(NewInitCmd())
	cmd.AddCommand(NewIPCmd())
	cmd.AddCommand(NewMetaCmd())
	cmd.AddCommand(NewRetrohuntCmd())
	cmd.AddCommand(NewScanCmd())
	cmd.AddCommand(NewSearchCmd())
	cmd.AddCommand(NewURLCmd())
	cmd.AddCommand(NewVersionCmd())

	return cmd
}
