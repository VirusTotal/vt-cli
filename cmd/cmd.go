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
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/fatih/color"
	"github.com/spf13/pflag"

	"github.com/VirusTotal/vt-cli/utils"
	"github.com/VirusTotal/vt-cli/yaml"
)

var colorScheme = yaml.Colors{
	KeyColor:     color.New(color.FgYellow),
	ValueColor:   color.New(color.FgHiGreen),
	CommentColor: color.New(color.Faint)}

func addAPIKeyFlag(flags *pflag.FlagSet) {
	flags.StringP(
		"apikey", "k", "",
		"API key")
}

func addFormatFlag(flags *pflag.FlagSet) {
	flags.String(
		"format", "yaml",
		"Output format (yaml/json/csv)")
}

func addHostFlag(flags *pflag.FlagSet) {
	flags.String(
		"host", "www.virustotal.com",
		"API host name")
	flags.MarkHidden("host")
}

func addProxyFlag(flags *pflag.FlagSet) {
	flags.String(
		"proxy", "",
		"HTTP proxy")
	flags.MarkHidden("proxy")
}

func addIncludeExcludeFlags(flags *pflag.FlagSet) {
	flags.StringSliceP(
		"include", "i", []string{"**"},
		"include fields matching the provided pattern")

	flags.StringSliceP(
		"exclude", "x", []string{},
		"exclude fields matching the provided pattern")
}

func addThreadsFlag(flags *pflag.FlagSet) {
	flags.IntP(
		"threads", "t", 5,
		"number of threads working in parallel")
}

func addIDOnlyFlag(flags *pflag.FlagSet) {
	flags.BoolP(
		"identifiers-only", "I", false,
		"print identifiers only")
}

func addLimitFlag(flags *pflag.FlagSet) {
	flags.IntP(
		"limit", "n", 10,
		"maximum number of results")
}

func addCursorFlag(flags *pflag.FlagSet) {
	flags.StringP(
		"cursor", "c", "",
		"cursor for continuing where the previous request left")
}

func addOutputFlag(flags *pflag.FlagSet) {
	flags.StringP(
		"output", "o", ".",
		"directory where downloaded files are put")
}

func addPrivateFlag(flags *pflag.FlagSet) {
	flags.BoolP(
		"private", "P", false,
		"include private ones (requires private scanning privileges)")
}

func addFilterFlag(flags *pflag.FlagSet) {
	flags.StringP(
		"filter", "f", "",
		"filter")
}

func addVerboseFlag(flags *pflag.FlagSet) {
	flags.BoolP(
		"verbose", "v", false,
		"verbose output")
}

func addSilentFlag(flags *pflag.FlagSet) {
	flags.BoolP(
		"silent", "s", false,
		"Silent or quiet mode. Do not show progress meter")
}

func addHumanFlag(flags *pflag.FlagSet) {
	flags.BoolP(
		"human", "H", false,
		"output in a human-friendly format")
}

// ReadFile reads the specified file and returns its content. If filename is "-"
// the data is read from stdin.
func ReadFile(filename string) ([]byte, error) {
	if filename == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(filename)
}

// NewAPIClient returns a new utils.APIClient.
func NewAPIClient() (*utils.APIClient, error) {
	return utils.NewAPIClient(fmt.Sprintf("vt-cli %s", Version))
}

// NewPrinter creates a new utils.Printer.
func NewPrinter(cmd *cobra.Command) (*utils.Printer, error) {
	client, err := NewAPIClient()
	if err != nil {
		return nil, err
	}
	return utils.NewPrinter(client, cmd, &colorScheme)
}
