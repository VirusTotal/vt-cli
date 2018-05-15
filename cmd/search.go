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

	"github.com/spf13/viper"

	"github.com/VirusTotal/vt-cli/utils"
	"github.com/VirusTotal/vt-go/vt"
	"github.com/spf13/cobra"
)

func preRunSearchCmd(c *cobra.Command, args []string) error {

	if viper.GetBool("download") {
		for _, flag := range []string{"include", "identifiers-only"} {
			if c.Flag(flag).Changed {
				return fmt.Errorf("--%s can't be used with --download", flag)
			}
		}
	} else {
		for _, flag := range []string{"output", "threads"} {
			if c.Flag(flag).Changed {
				return fmt.Errorf("--%s must be used with --download", flag)
			}
		}
	}

	return nil
}

func runSearchCmd(cmd *cobra.Command, args []string) error {

	batchSize := 25
	if viper.GetInt("limit") < batchSize {
		batchSize = viper.GetInt("limit")
	}

	options := vt.SearchOptions{}
	options.Limit = viper.GetInt("limit")
	options.Cursor = viper.GetString("cursor")
	options.BatchSize = batchSize
	options.DescriptorsOnly = viper.GetBool("identifiers-only") || viper.GetBool("download")

	client, err := utils.NewAPIClient()
	if err != nil {
		return err
	}

	it, err := client.Search(args[0], options)
	if err != nil {
		return err
	}

	if viper.GetBool("download") {
		ch := make(chan string)
		go func() {
			for it.Next() {
				obj := it.Get()
				ch <- obj.ID
			}
			close(ch)
		}()
		d := &downloader{client: client}
		c := utils.NewCoordinator(viper.GetInt("threads"))
		c.DoWithArgCh(d, ch)
	} else {
		p, err := NewObjectPrinter()
		if err != nil {
			return err
		}
		return p.PrintIter(it)
	}

	return nil
}

var cmdSearchHelp = `Search for files using VirusTotal Intelligence's query language.`

var cmdSearchExample = `  vt search eicar
  vt search "foobar p:1+"`

// NewSearchCmd returns a new instance of the 'search' command.
func NewSearchCmd() *cobra.Command {

	cmd := &cobra.Command{
		Args:    cobra.ExactArgs(1),
		Use:     "search [query]",
		Short:   "Search for files in VirusTotal Intelligence",
		Long:    cmdSearchHelp,
		Example: cmdSearchExample,
		PreRunE: preRunSearchCmd,
		RunE:    runSearchCmd,
	}

	cmd.Flags().BoolP("download", "d", false, "download files")

	addIDOnlyFlag(cmd.Flags())
	addIncludeExcludeFlags(cmd.Flags())
	addThreadsFlag(cmd.Flags())
	addLimitFlag(cmd.Flags())
	addCursorFlag(cmd.Flags())
	addOutputFlag(cmd.Flags())

	return cmd
}
