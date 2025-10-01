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
	"encoding/base64"
	"regexp"

	"github.com/VirusTotal/vt-cli/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var urlCmdHelp = `Get information about one or more URLs.

This command receives one or more URLs and returns information about them. URL
hashes as returned in the "object_id" field are also accepted. The information
about each URL is returned in the same order as the URLs are passed to the
command.

If the command receives a single hypen (-) the URLs are read from the standard
input, one per line.
`

var urlCmdExample = `  vt url https://www.virustotal.com
  vt url f1177df4692356280844e1d5af67cc4a9eccecf77aa61c229d483b7082c70a8e
  cat list_of_urls | vt url -`

// Regular expressions used for validating a URL identifier.
var urlID = regexp.MustCompile(`[0-9a-fA-F]{64}`)

// NewURLCmd returns a new instance of the 'url' command.
func NewURLCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "url [url]...",
		Short:   "Get information about URLs",
		Long:    urlCmdHelp,
		Example: urlCmdExample,
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			r := utils.NewMappedStringReader(
				utils.StringReaderFromCmdArgs(args),
				func(url string) string {
					if urlID.MatchString(url) {
						// The user provided a URL identifier as returned by
						// VirusTotal's API, which consists in the URL's SHA-256.
						// In that case use the identifier as is.
						return url
					}
					// If the user provides an actual URL, it needs to be
					// encoded as base64 before being used.
					return base64.RawURLEncoding.EncodeToString([]byte(url))
				})

			if viper.GetBool("private") {
				return p.GetAndPrintObjectsWithFallback(
					[]string{"urls/%s", "private/urls/%s"},
					r,
					nil)
			} else {
				return p.GetAndPrintObjects(
					"urls/%s",
					r,
					nil)
			}
		},
	}

	addRelationshipCmds(cmd, "urls", "url", "[url]", true)

	addThreadsFlag(cmd.Flags())
	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())
	addPrivateFlag(cmd.Flags())

	return cmd
}
