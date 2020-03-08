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
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	humanize "github.com/dustin/go-humanize"

	vt "github.com/VirusTotal/vt-go"
	"github.com/gosuri/uitable"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rulesPattern = regexp.MustCompile(`rule\s+(\w+)\s*(:(\s*\w+\s*)+)?{`)

func retrohuntListTable(cmd *cobra.Command) error {

	client, err := NewAPIClient()
	if err != nil {
		return err
	}

	limit := 0
	if cmd.Flag("limit").Changed {
		limit = viper.GetInt("limit")
	}

	it, err := client.Iterator(
		vt.URL("intelligence/retrohunt_jobs"),
		vt.IteratorLimit(limit),
		vt.IteratorFilter(viper.GetString("filter")))

	if err != nil {
		return err
	}
	defer it.Close()

	table := uitable.New()

	table.AddRow(
		"JOB ID", "CREATED", "STARTED", "STATUS", "ETA", "SCANNED",
		"MATCHES", "RULES")

	table.RightAlign(5)
	table.RightAlign(6)

	for it.Next() {
		job := it.Get()
		status := job.MustGetString("status")
		startDate := "not yet"
		if s, err := job.GetTime("start_date"); err == nil {
			startDate = humanize.Time(s)
		}

		if status == "queued" || status == "running" {
			status = fmt.Sprintf("%s (%.1f%%)", status, job.MustGetFloat64("progress"))
		}

		eta := "-"
		if e, err := job.GetInt64("eta_seconds"); err == nil {
			eta = time.Duration(e * 1000000000).String()
		}

		rules, _ := job.GetString("rules")
		matches := rulesPattern.FindAllStringSubmatch(rules, 5)
		ruleNames := make([]string, len(matches))

		for i, m := range matches {
			ruleNames[i] = m[1]
		}

		rules = strings.Join(ruleNames, ", ")

		if len(rules) > 40 {
			rules = rules[0:40] + "…"
		}

		creationDate, _ := job.GetTime("creation_date")
		scannedBytes, _ := job.GetInt64("scanned_bytes")
		numMatches, _ := job.GetInt64("num_matches")

		table.AddRow(
			job.ID(),
			humanize.Time(creationDate),
			startDate,
			status,
			eta,
			humanize.Bytes(uint64(scannedBytes)),
			humanize.Comma(numMatches),
			rules)
	}

	fmt.Println(table)

	return it.Error()
}

// NewRetrohuntListCmd returns a new instance of the 'list' command.
func NewRetrohuntListCmd() *cobra.Command {

	cmd := &cobra.Command{
		Aliases: []string{"ls"},
		Use:     "list",
		Short:   "List retrohunt jobs",
		Long:    `List retrohunt jobs.`,

		RunE: func(cmd *cobra.Command, args []string) error {
			if viper.GetBool("human") {
				for _, flag := range []string{"cursor", "include", "exclude"} {
					if cmd.Flag(flag).Changed {
						return fmt.Errorf("--%s can't be used with --human", flag)
					}
				}
				return retrohuntListTable(cmd)
			}
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.PrintCollection(vt.URL("intelligence/retrohunt_jobs"))
		},
	}

	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())
	addFilterFlag(cmd.Flags())
	addLimitFlag(cmd.Flags())
	addCursorFlag(cmd.Flags())
	addHumanFlag(cmd.Flags())

	return cmd
}

var retrohuntStartCmdHelp = `Start a retrohunt job.

This command receives a file containing YARA rules and starts a retrohunt job with those rules.`

// NewRetrohuntStartCmd returns a new instance of the 'start' command.
func NewRetrohuntStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start [file]",
		Short: "Start a retrohunt job",
		Long:  retrohuntStartCmdHelp,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			client, err := NewAPIClient()
			if err != nil {
				return err
			}

			var rules []byte
			if args[0] == "-" {
				rules, err = ioutil.ReadAll(os.Stdin)
			} else {
				rules, err = ioutil.ReadFile(args[0])
			}
			if err != nil {
				return err
			}

			obj := vt.NewObject("retrohunt_job")
			obj.SetString("rules", string(rules))
			obj.SetString("corpus", viper.GetString("corpus"))

			before := viper.GetString("before")
			after := viper.GetString("after")

			var timeRange map[string]int64

			if before != "" || after != "" {
				timeRange = make(map[string]int64)
				obj.Set("time_range", timeRange)
			}

			if after != "" {
				if t, err := time.Parse("2006-01-02", after); err == nil {
					timeRange["start"] = t.Unix()
				} else {
					return err
				}
			}

			if before != "" {
				if t, err := time.Parse("2006-01-02", before); err == nil {
					timeRange["end"] = t.Unix()
				} else {
					return err
				}
			}

			err = client.PostObject(vt.URL("intelligence/retrohunt_jobs"), obj)
			if err != nil {
				return err
			}

			fmt.Println(obj.ID())
			return nil
		},
	}

	cmd.Flags().String(
		"before", "",
		"scan files sent to VirusTotal before the given date (format: YYYY-MM-DD)")

	cmd.Flags().String(
		"after", "",
		"scan files sent to VirusTotal after the given date (format: YYYY-MM-DD)")

	cmd.Flags().String(
		"corpus", "main",
		"specify the corpus that will be scanned, possible values are \"main\" and \"goodware\"")

	cmd.MarkZshCompPositionalArgumentFile(1)

	return cmd
}

// NewRetrohuntAbortCmd returns a new instance of the 'abort' command.
func NewRetrohuntAbortCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "abort [job id]",
		Short: "Abort a retrohunt job",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			url := vt.URL("intelligence/retrohunt_jobs/%s/abort", args[0])
			_, err = client.Post(url, nil)
			return err
		},
	}
}

// NewRetrohuntDeleteCmd returns a new instance of the 'delete' command.
func NewRetrohuntDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Aliases: []string{"del", "rm"},
		Use:     "delete [job id]...",
		Short:   "Delete a retrohunt job",
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := NewAPIClient()
			if err != nil {
				return err
			}

			var wg sync.WaitGroup
			for _, arg := range args {
				wg.Add(1)
				go func(jobID string) {
					url := vt.URL("intelligence/retrohunt_jobs/%s", jobID)
					if _, err := client.Delete(url); err != nil {
						fmt.Fprintf(os.Stderr, "%v\n", err)
					}
					wg.Done()
				}(arg)
			}

			wg.Wait()
			return nil
		},
	}
}

// NewRetrohuntMatchesCmd returns a new instance of the 'matches' command.
func NewRetrohuntMatchesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "matches [job id]",
		Short: "Get matches for a retrohunt job",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.PrintCollection(vt.URL("intelligence/retrohunt_jobs/%s/matching_files", args[0]))
		},
	}

	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())
	addLimitFlag(cmd.Flags())
	addCursorFlag(cmd.Flags())

	return cmd
}

// NewRetrohuntCmd returns a new instance of the 'retrohunt' command.
func NewRetrohuntCmd() *cobra.Command {

	cmd := &cobra.Command{
		Aliases: []string{"rh"},
		Use:     "retrohunt [id]...",
		Short:   "Manage retrohunt jobs",
		Long:    `Manage retrohunt jobs.`,
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			re, _ := regexp.Compile("\\w+-\\d+")
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.GetAndPrintObjects("intelligence/retrohunt_jobs/%s", args, re)
		},
	}

	addThreadsFlag(cmd.Flags())

	cmd.AddCommand(NewRetrohuntAbortCmd())
	cmd.AddCommand(NewRetrohuntDeleteCmd())
	cmd.AddCommand(NewRetrohuntListCmd())
	cmd.AddCommand(NewRetrohuntMatchesCmd())
	cmd.AddCommand(NewRetrohuntStartCmd())

	return cmd
}
