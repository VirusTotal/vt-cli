// Copyright © 2017 VirusTotal CLI authors. All Rights Reserved.
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

package main

import (
	"fmt"
	"os"
	"path"

	"github.com/VirusTotal/vt-cli/cmd"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Migrate old ~/.vt.* configuration files.
func migrateConfig(configDir string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	for _, ext := range viper.SupportedExts {
		oldPath := path.Join(home, ".vt."+ext)

		f, err := os.Open(oldPath)
		if f != nil {
			f.Close()
		}
		if err != nil {
			continue
		}

		newPath := path.Join(configDir, path.Base(oldPath))
		err = os.Rename(oldPath, newPath)
		if err != nil {
			fmt.Printf("Migrated %s to %s\n", oldPath, newPath)
		} else {
			fmt.Printf("Failed to migrate %s to %s: %v\n", oldPath, newPath, err)
		}
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	// Find config directory.
	configDir, err := os.UserConfigDir()
	if err == nil {
		configDir = path.Join(configDir, "vt-cli")
		migrateConfig(configDir)

		viper.AddConfigPath(configDir)
	}
	// Search config in current directory
	viper.AddConfigPath(".")
	// Config file must be named vt + format extension (.toml, .json, etc)
	viper.SetConfigName("vt")

	// The prefix for all environment variables will be VTCLI_. Examples:
	// VTCLI_PROXY, VTCLI_APIKEY.
	viper.SetEnvPrefix("VTCLI")

	// Read in environment variables that match
	viper.AutomaticEnv()

	// If a config file is found, read it in.
	viper.ReadInConfig()
}

func init() {
	cobra.OnInitialize(initConfig)
}

func main() {
	vtCmd := cmd.NewVTCommand()
	if err := vtCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
