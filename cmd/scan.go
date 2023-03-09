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
	"context"
	"fmt"
	"os"
	"time"

	"github.com/VirusTotal/vt-cli/utils"
	vt "github.com/VirusTotal/vt-go"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// Poll frequency defines the interval in which requests are sent to the
	// VT API to check if the analysis is completed.
	POLL_FREQUENCY = 10 * time.Second
	// Timeout limit defines the maximum amount of seconds to wait for an
	// analysis' results
	TIMEOUT_LIMIT = 120 * time.Second
)

// waitForAnalysisResults calls every pollFrequency seconds to the VT API and
// checks whether an analysis is completed or not. When the analysis is completed
// it is returned.
func waitForAnalysisResults(cli *utils.APIClient, analysisId string) (*vt.Object, error) {
	ticker := time.NewTicker(POLL_FREQUENCY)
	defer ticker.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), TIMEOUT_LIMIT)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if obj, err := cli.GetObject(vt.URL(fmt.Sprintf("analyses/%s", analysisId))); err != nil {
				return nil, fmt.Errorf("error retrieving analysis result: %v", err)
			} else if status, _ := obj.Get("status"); status == "completed" {
				return obj, nil
			}
		}
	}
}

type fileScanner struct {
	scanner           *vt.FileScanner
	cli               *utils.APIClient
	printer           *utils.Printer
	showInVT          bool
	waitForCompletion bool
}

func (s *fileScanner) Do(path interface{}, ds *utils.DoerState) string {

	progressCh := make(chan float32)
	defer close(progressCh)

	go func() {
		for progress := range progressCh {
			if progress < 100 {
				ds.Progress = fmt.Sprintf("%s uploading... %4.1f%%", path, progress)
			} else {
				ds.Progress = fmt.Sprintf("%s scanning...", path)
			}
		}
	}()

	f, err := os.Open(path.(string))
	if err != nil {
		return fmt.Sprintf("%s", err)
	}
	defer f.Close()

	analysis, err := s.scanner.ScanFile(f, progressCh)
	if err != nil {
		return fmt.Sprintf("%s", err)
	}

	if s.showInVT {
		// Return the analysis URL in VT so users can visit it
		return fmt.Sprintf(
			"%s https://www.virustotal.com/gui/file-analysis/%s",
			path.(string), analysis.ID())
	}

	if s.waitForCompletion {
		analysisResult, err := waitForAnalysisResults(s.cli, analysis.ID())
		if err != nil {
			return fmt.Sprintf("%s", err)
		}
		s.printer.PrintObject(analysisResult)
		return ""
	}

	return fmt.Sprintf("%s %s", path.(string), analysis.ID())
}

var scanFileCmdHelp = `Scan one or more files.

This command receives one or more file paths and uploads them to VirusTotal for
scanning. It returns the file paths followed by their corresponding analysis IDs.
You can use the "vt analysis" command for retrieving information about the
analyses or you can use the --wait flag to see the results when the
analysis is completed.

If the command receives a single hypen (-) the file paths are read from the standard
input, one per line.

The command can also receive a directory to scan all files contained on it.`

var scanFileCmdExample = `  vt scan file foo.exe
  vt scan file foo.exe bar.exe
	vt scan file foo/
  cat list_of_file_paths | vt scan file -`

// NewScanFileCmd returns a new instance of the 'scan file' command.
func NewScanFileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "file [[dir] | [file]...]",
		Short:   "Scan one or more files",
		Long:    scanFileCmdHelp,
		Example: scanFileCmdExample,
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			c := utils.NewCoordinator(viper.GetInt("threads"))
			var argReader utils.StringReader
			if len(args) == 1 && args[0] == "-" {
				argReader = utils.NewStringIOReader(os.Stdin)
			} else if len(args) == 1 && utils.IsDir(args[0]) {
				argReader, _ = utils.NewFileDirReader(args[0])
			} else {
				argReader = utils.NewStringArrayReader(args)
			}
			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			s := &fileScanner{
				scanner:           client.NewFileScanner(),
				showInVT:          viper.GetBool("open"),
				waitForCompletion: viper.GetBool("wait"),
				printer:           p,
				cli:               client}
			c.DoWithStringsFromReader(s, argReader)
			return nil
		},
	}

	addThreadsFlag(cmd.Flags())
	addOpenInVTFlag(cmd.Flags())
	addWaitForCompletionFlag(cmd.Flags())
	cmd.MarkZshCompPositionalArgumentFile(1)

	return cmd
}

type urlScanner struct {
	scanner           *vt.URLScanner
	cli               *utils.APIClient
	printer           *utils.Printer
	showInVT          bool
	waitForCompletion bool
}

func (s *urlScanner) Do(url interface{}, ds *utils.DoerState) string {
	analysis, err := s.scanner.Scan(url.(string))
	if err != nil {
		return fmt.Sprintf("%s", err)
	}

	if s.showInVT {
		return fmt.Sprintf(
			"%s https://www.virustotal.com/gui/url-analysis/%s", url, analysis.ID())
	}

	if s.waitForCompletion {
		analysisResult, err := waitForAnalysisResults(s.cli, analysis.ID())
		if err != nil {
			return fmt.Sprintf("%s", err)
		}
		s.printer.PrintObject(analysisResult)
		return ""
	}

	return fmt.Sprintf("%s %s", url, analysis.ID())
}

var scanURLCmdHelp = `Scan one or more URLs.

This command receives one or more URLs and scan them. It returns the URLs followed
by their corresponding analysis IDs. You can use the "vt analysis" command for
retrieving information about the analyses or you can use the --wait
flag to see the results when the analysis is completed.

If the command receives a single hypen (-) the URLs are read from the standard
input, one per line.`

var scanURLCmdExample = `  vt scan url http://foo.com
  vt scan url http://foo.com http://bar.com
  cat list_of_urls | vt scan urls -`

// NewScanURLCmd returns a new instance of the 'scan url' command.
func NewScanURLCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:     "url [url]...",
		Short:   "Scan one of more URLs",
		Long:    scanURLCmdHelp,
		Example: scanURLCmdExample,
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			c := utils.NewCoordinator(viper.GetInt("threads"))
			var argReader utils.StringReader
			if len(args) == 1 && args[0] == "-" {
				argReader = utils.NewStringIOReader(os.Stdin)
			} else {
				argReader = utils.NewStringArrayReader(args)
			}
			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			s := &urlScanner{
				scanner:           client.NewURLScanner(),
				showInVT:          viper.GetBool("open"),
				waitForCompletion: viper.GetBool("wait"),
				printer:           p,
				cli:               client}
			c.DoWithStringsFromReader(s, argReader)
			return nil
		},
	}

	addThreadsFlag(cmd.Flags())
	addOpenInVTFlag(cmd.Flags())
	addWaitForCompletionFlag(cmd.Flags())

	return cmd
}

var scanCmdHelp = `Scan files or URLs.

This group of commands allow to scan files and URLs.`

// NewScanCmd returns a new instance of the 'scan' command.
func NewScanCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan files or URLs",
		Long:  scanCmdHelp,
	}

	cmd.AddCommand(NewScanURLCmd())
	cmd.AddCommand(NewScanFileCmd())

	return cmd
}

func addOpenInVTFlag(flags *pflag.FlagSet) {
	flags.BoolP(
		"open", "o", false,
		"Return an URL to see the analysis report at the VirusTotal web GUI")
}

func addWaitForCompletionFlag(flags *pflag.FlagSet) {
	flags.BoolP(
		"wait", "w", false,
		"Wait until the analysis is completed and show the analysis results")
}
