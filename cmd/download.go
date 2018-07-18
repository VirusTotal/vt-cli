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
	"os"
	"path"
	"regexp"
	"time"

	"github.com/VirusTotal/vt-cli/utils"
	"github.com/VirusTotal/vt-go/vt"
	"github.com/cavaliercoder/grab"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type downloadCallback func(grabResp *grab.Response)

// downloadFile downloads a file given a hash (SHA-256, SHA-1 or MD5)
func downloadFile(client *utils.APIClient, hash string, callback downloadCallback) error {
	var downloadURL string

	// Get download URL
	u := vt.URL("files/%s/download_url", hash)
	if _, err := client.GetData(u, &downloadURL); err != nil {
		return err
	}

	// We have the download URL, let's grab the file
	c := grab.NewClient()
	req, err := grab.NewRequest(path.Join(viper.GetString("output"), hash), downloadURL)
	if err != nil {
		return err
	}

	resp := c.Do(req)
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()

Loop:
	for {
		select {
		case <-t.C:
			callback(resp)
		case <-resp.Done:
			callback(resp)
			break Loop
		}
	}
	return nil
}

type downloader struct {
	client *utils.APIClient
}

func (d *downloader) Do(file interface{}, ds *utils.DoerState) string {

	var hash string
	if f, isObject := file.(*vt.Object); isObject {
		hash = f.ID
	} else {
		hash = file.(string)
	}

	ds.Progress = fmt.Sprintf("%s %4.1f%%", hash, 0.0)
	err := downloadFile(d.client, hash, func(resp *grab.Response) {
		progress := 100 * resp.Progress()
		if progress < 100 {
			ds.Progress = fmt.Sprintf("%s %4.1f%% %6.1f KBi/s",
				hash, progress, resp.BytesPerSecond()/1024)
		}
	})

	msg := color.GreenString("ok")
	if err != nil {
		if apiErr, ok := err.(vt.Error); ok && apiErr.Code == "NotFoundError" {
			msg = color.RedString("not found")
		} else {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	return fmt.Sprintf("%s [%s]", hash, msg)
}

var downloadCmdHelp = `Download one or more files.

This command receives one or more file hashes (SHA-256, SHA-1 or MD5) and
downloads the files from VirusTotal. For using this command you need an API
key with access to VirusTotal Intelligence.

If the command receives a single hypen (-) the hashes are read from the standard
input, one per line.`

var downladCmdExample = `  vt download 8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85
  vt download 76cdb2bad9582d23c1f6f4d868218d6c 44d88612fea8a8f36de82e1278abb02f
  cat list_of_hashes | vt download -`

// NewDownloadCmd returns a new instance of the 'download' command.
func NewDownloadCmd() *cobra.Command {

	cmd := &cobra.Command{
		Aliases: []string{"dl"},
		Use:     "download",
		Short:   "Download files",
		Long:    downloadCmdHelp,
		Example: downladCmdExample,
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			c := utils.NewCoordinator(viper.GetInt("threads"))
			var argReader utils.StringReader
			if len(args) == 1 && args[0] == "-" {
				argReader = utils.NewStringIOReader(os.Stdin)
			} else {
				argReader = utils.NewStringArrayReader(args)
			}
			client, err := utils.NewAPIClient()
			if err != nil {
				return err
			}
			d := &downloader{client: client}
			re, _ := regexp.Compile(`^([[:xdigit:]]{64}|[[:xdigit:]]{40}|[[:xdigit:]]{32})$`)
			c.DoWithStringsFromReader(d, utils.NewFilteredStringReader(argReader, re))
			return nil
		},
	}

	addThreadsFlag(cmd.Flags())
	addOutputFlag(cmd.Flags())

	return cmd
}
