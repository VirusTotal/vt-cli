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
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// NewGenDocCmd returns a new instance of the 'gendoc' command.
func NewGenDocCmd() *cobra.Command {
	return &cobra.Command{
		Hidden: true,
		Use:    "gendoc [output dir]",
		Short:  "Generate documentation",
		Args:   cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			outputDir := "."
			if len(args) == 1 {
				outputDir = args[0]
			}
			return doc.GenMarkdownTree(cmd.Parent(), outputDir)
		},
	}
}
