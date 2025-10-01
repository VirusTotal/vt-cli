// Copyright © 2019 The VirusTotal CLI authors. All Rights Reserved.
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
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"

	"github.com/VirusTotal/vt-cli/utils"
	vt "github.com/VirusTotal/vt-go"
	grab "github.com/cavaliergopher/grab/v3"
	"github.com/fatih/color"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var monitorPartnerItemsCmdExample = `  vt monitorpartner list
  vt monitorpartner list --filter "engine:<EngineName>" --include sha256,first_detection_date`

// NewMonitorPartnerHashesListCmd returns a list or monitor_partner according to a filter.
func NewMonitorPartnerHashesListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List available monitor partner hashes",
		Example: monitorPartnerItemsCmdExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.PrintCollection(vt.URL("monitor_partner/hashes"))
		},
	}

	addIncludeExcludeFlags(cmd.Flags())
	addFilterFlag(cmd.Flags())
	addLimitFlag(cmd.Flags())
	addCursorFlag(cmd.Flags())

	return cmd
}

// Monitor Partner downloader, it implements the Doer interface. Retrieves the item
// path to know the destination filename and downloads and save each individual
// file using fileDownloader.DownloadFile
type monitorPartnerDownloader struct {
	fileDownloader
}

func (d *monitorPartnerDownloader) Do(file interface{}, ds *utils.DoerState) string {
	var hash string
	if f, isObject := file.(*vt.Object); isObject {
		hash = f.ID()
	} else {
		hash = file.(string)
	}

	ds.Progress = fmt.Sprintf("%s %4.1f%%", hash, 0.0)

	// Get download URL
	var downloadURL string
	_, err := d.client.GetData(vt.URL("monitor_partner/files/%s/download_url", hash), &downloadURL)

	if err == nil {
		dstPath := path.Join(viper.GetString("output"), hash)
		err = d.DownloadFile(downloadURL, dstPath, func(resp *grab.Response) {
			progress := 100 * resp.Progress()
			if progress < 100 {
				ds.Progress = fmt.Sprintf("%s %4.1f%% %6.1f KBi/s",
					hash, progress, resp.BytesPerSecond()/1024)
			}
		})
	}

	msg := color.GreenString("ok")
	if err != nil {
		if apiErr, ok := err.(vt.Error); ok && apiErr.Code == "NotFoundError" {
			msg = color.RedString("not found")
		} else {
			msg = color.RedString(err.Error())
		}
	}

	return fmt.Sprintf("%s [%s]", hash, msg)
}

var monitorPartnerHashDownloadCmdHelp = `Download files from your partner account.

This command download files from your monitor partner account using their sha256.`

var monitorPartnerHashDownloadCmdExample = `  vt monitorpartner download <sha256-1> <sha256-2> ...
  cat list_of_monitor_ids | vt monitorpartner download -`

// NewMonitorPartnerHashDownloadCmd returns a command for downloading files from your
// monitor account.
func NewMonitorPartnerHashDownloadCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "download [sha256]...",
		Short:   "Download files from your monitor partner account",
		Long:    monitorPartnerHashDownloadCmdHelp,
		Example: monitorPartnerHashDownloadCmdExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			var argReader utils.StringReader
			if len(args) == 0 {
				return errors.New("No hash provided")
			} else if len(args) == 1 && args[0] == "-" {
				argReader = utils.NewStringIOReader(os.Stdin)
			} else {
				argReader = utils.NewStringArrayReader(args)
			}
			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			re, _ := regexp.Compile("[[:xdigit:]]{64}")
			monitorHashes := utils.NewFilteredStringReader(argReader, re)

			c := utils.NewCoordinator(viper.GetInt("threads"))
			c.DoWithStringsFromReader(
				&monitorPartnerDownloader{fileDownloader: newFileDownloader(client)},
				monitorHashes)
			return err
		},
	}

	addThreadsFlag(cmd.Flags())
	addOutputFlag(cmd.Flags())
	return cmd
}

var monitorPartnerCmdHelp = `Manage your VirusTotal Monitor Partner account.

This command allows you to list and retrieve files detected by your engine.

Reference:
  https://docs.virustotal.com/reference/monitor-partner`

// NewMonitorPartnerCmd returns a new instance of the 'monitor_hash' command.
func NewMonitorPartnerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "monitorpartner",
		Short: "Manage your monitor partner account",
		Long:  monitorPartnerCmdHelp,
		Args:  cobra.MinimumNArgs(1),
	}

	addThreadsFlag(cmd.Flags())
	addIncludeExcludeFlags(cmd.Flags())

	cmd.AddCommand(NewMonitorPartnerHashesListCmd())
	cmd.AddCommand(NewMonitorPartnerHashDownloadCmd())

	addRelationshipCmds(cmd, "monitor_partner/hashes", "monitor_hash", "[sha256]", false)

	return cmd
}
