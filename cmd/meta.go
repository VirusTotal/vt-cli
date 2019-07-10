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
	"os"

	"github.com/gobwas/glob"

	"github.com/VirusTotal/vt-cli/yaml"
	"github.com/spf13/cobra"
)

var metaCmdHelp = `Returns metadata about VirusTotal.

Metadata includes the full list of engines, relationships supported by each type
of objects, and other useful information.`

// NewMetaCmd returns a new instance of the 'meta' command.
func NewMetaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "meta",
		Short: "Returns metadata about VirusTotal",
		Long:  metaCmdHelp,

		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			metadata, err := client.GetMetadata()
			if err != nil {
				return err
			}
			return yaml.NewEncoder(os.Stdout,
				yaml.EncoderColors(&colorScheme),
				yaml.EncoderDateKeys([]glob.Glob{}),
			).Encode(metadata)
		},
	}
}
