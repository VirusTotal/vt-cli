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
	"strings"

	"github.com/spf13/viper"

	"github.com/VirusTotal/vt-cli/utils"
	vt "github.com/VirusTotal/vt-go"
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

	client, err := NewAPIClient()
	if err != nil {
		return err
	}

	it, err := client.Search(args[0],
		vt.WithLimit(viper.GetInt("limit")),
		vt.WithCursor(viper.GetString("cursor")),
		vt.WithBatchSize(batchSize),
		vt.WithDescriptorsOnly(
			viper.GetBool("identifiers-only") || viper.GetBool("download")))

	if err != nil {
		return err
	}

	if viper.GetBool("download") {
		ch := make(chan interface{})
		go func() {
			for it.Next() {
				obj := it.Get()
				ch <- obj.ID
			}
			close(ch)
		}()
		c := utils.NewCoordinator(viper.GetInt("threads"))
		c.DoWithItemsFromChannel(&downloader{client: client}, ch)
		return it.Error()
	}

	p, err := NewObjectPrinter(cmd)
	if err != nil {
		return err
	}
	return p.PrintIter(it)
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

	cmd.AddCommand(NewContentSearchCmd())

	return cmd
}

type matchPrinter struct {
	client *utils.APIClient
	idOnly bool
}

func (m *matchPrinter) Do(fileObj interface{}, ds *utils.DoerState) string {
	f := fileObj.(*vt.Object)
	var line string
	if m.idOnly {
		line = f.ID
	} else {
		var s string
		confidence, _ := f.GetContextAttributeFloat64("confidence")
		snippetID, _ := f.GetContextAttributeString("snippet")
		inSubFile, _ := f.GetContextAttributeString("match_in_subfile")
		snippets := make([]string, 0)
		_, err := m.client.GetData(vt.URL("intelligence/search/snippets/%s", snippetID), &snippets)
		if err == nil {
			s = strings.Join(snippets, "\n\n")
			s = strings.Replace(s, "\x1c", "\033[1m", -1)
			s = strings.Replace(s, "\x1d", "\033[0m", -1)
		} else {
			s = "<no snippet available>"
		}
		line = fmt.Sprintf(
			"%s\n\nsha256  : %s\nscore   : %03.1f \nsubfile : %v\n\n%s\n",
			strings.Repeat("_", 76), f.ID, confidence, inSubFile, s)
	}
	return line
}

func getIgnoredSubstrings(meta map[string]interface{}) []string {
	if i, ok := meta["ignored_substrings"]; ok {
		ii := i.([]interface{})
		ss := make([]string, len(ii))
		for i := range ss {
			ss[i] = ii[i].(string)
		}
		return ss
	}
	return nil
}

func runContentSearchCmd(cmd *cobra.Command, args []string) error {

	batchSize := 10
	if viper.GetInt("limit") < batchSize {
		batchSize = viper.GetInt("limit")
	}

	client, err := NewAPIClient()
	if err != nil {
		return err
	}

	terms := make([]string, len(args))
	for i, arg := range args {
		terms[i] = fmt.Sprintf("content:%s", arg)
	}

	it, err := client.Search(strings.Join(terms, " "),
		vt.WithLimit(viper.GetInt("limit")),
		vt.WithCursor(viper.GetString("cursor")),
		vt.WithBatchSize(batchSize),
		vt.WithDescriptorsOnly(
			viper.GetBool("identifiers-only") || viper.GetBool("download")))

	if err != nil {
		return err
	}

	c := utils.NewCoordinator(viper.GetInt("threads"))

	var doer utils.Doer
	if viper.GetBool("download") {
		doer = &downloader{client: client}
	} else {
		doer = &matchPrinter{client, viper.GetBool("identifiers-only")}
		c.EnableSpinner()
	}

	c.DoWithObjectsFromIterator(doer, it, batchSize)

	if ignored := getIgnoredSubstrings(it.Meta()); ignored != nil {
		colorScheme.CommentColor.Printf(
			"IGNORED SUBSTRINGS:\n%s\n",
			strings.Join(ignored, "\n"))
	}

	PrintCommandLineWithCursor(cmd, it)
	return it.Error()
}

var cmdContentSearchHelp = `Search for content within files in VirusTotal`

var cmdContentSearchExample = `  vt search content '{cafebabe}'
  vt search content '{70 6C 75 73 76 69 63 [1] 79 61 72 61}'
  vt search content '/virustotal(.org|.com)/'`

// NewContentSearchCmd returns a new instance of the 'search content' command.
func NewContentSearchCmd() *cobra.Command {

	cmd := &cobra.Command{
		Args:    cobra.MinimumNArgs(1),
		Use:     "content [query]",
		Short:   "Search for patterns within files in VirusTotal Intelligence",
		Long:    cmdContentSearchHelp,
		Example: cmdContentSearchExample,
		RunE:    runContentSearchCmd,
	}

	cmd.Flags().BoolP("download", "d", false, "download files")
	cmd.Flags().BoolP("exact-matches-only", "e", false, "exact matches only")

	addThreadsFlag(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())
	addLimitFlag(cmd.Flags())
	addCursorFlag(cmd.Flags())

	return cmd
}
