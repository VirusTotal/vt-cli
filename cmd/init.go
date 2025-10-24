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
	"encoding/gob"
	"fmt"
	"os"
	"path"

	vt "github.com/VirusTotal/vt-go"
	"github.com/spf13/cobra"
)

var initCmdHelp = `Initialize or re-initialize this command-line tool.

This command will ask for your API key and save it in a local file, so you don't
need to enter it everytime you use the tool. It will also retrieve additional
metadata from VirusTotal for making the tool even more powerful.`

var vtBanner = `
██╗   ██╗██╗██████╗ ██╗   ██╗███████╗████████╗ ██████╗ ████████╗ █████╗ ██╗
██║   ██║██║██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔═══██╗╚══██╔══╝██╔══██╗██║
██║   ██║██║██████╔╝██║   ██║███████╗   ██║   ██║   ██║   ██║   ███████║██║
╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║   ██║   ██║   ██║   ██║   ██╔══██║██║
 ╚████╔╝ ██║██║  ██║╚██████╔╝███████║   ██║   ╚██████╔╝   ██║   ██║  ██║███████╗
  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝

VirusTotal Command-Line Interface: Threat Intelligence at your fingertips.

`

// NewInitCmd returns a 'init' command.
func NewInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize or re-initialize vt command-line tool",
		Long:  initCmdHelp,

		Run: func(cmd *cobra.Command, args []string) {

			fmt.Print(vtBanner)

			apiKey := cmd.Flags().Lookup("apikey").Value.String()

			if apiKey == "" {
				fmt.Print("Enter your API key: ")
				fmt.Scanln(&apiKey)
			}

			client := vt.NewClient(apiKey)

			metadata, err := client.GetMetadata()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			homeDir, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			cacheDir, err := os.UserCacheDir()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			relCacheFile, err := os.Create(path.Join(cacheDir, ".vt.relationships.cache"))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			defer relCacheFile.Close()

			enc := gob.NewEncoder(relCacheFile)

			if err := enc.Encode(metadata.Relationships); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			configFilePath := path.Join(homeDir, ".vt.toml")
			configFile, err := os.OpenFile(configFilePath, os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			defer configFile.Close()

			_, err = fmt.Fprintf(configFile, "apikey=\"%s\"\n", apiKey)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			fmt.Printf("API key written to config file: %s\n", configFilePath)
			fmt.Printf("Relationships cache written to: %s\n", relCacheFile.Name())
		},
	}
}
