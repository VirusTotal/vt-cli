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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"time"

	"github.com/VirusTotal/vt-cli/utils"
	vt "github.com/VirusTotal/vt-go"
	"github.com/briandowns/spinner"
	"github.com/cavaliercoder/grab"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type downloadCallback func(grabResp *grab.Response)

// downloadFile downloads a file given a hash (SHA-256, SHA-1 or MD5)
func downloadFile(client *utils.APIClient, downloadURL, dstPath string, callback downloadCallback) error {

	c := grab.NewClient()
	req, err := grab.NewRequest(dstPath, downloadURL)
	if err != nil {
		return err
	}

	req.HTTPRequest.Header.Add("x-apikey", client.APIKey)

	resp := c.Do(req)
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()

Loop:
	for {
		select {
		case <-t.C:
			callback(resp)
		case <-resp.Done:
			if err := resp.Err(); err != nil {
				return fmt.Errorf("download error: %+v", err)
			}
			callback(resp)
			break Loop
		}
	}
	return nil
}

// Standard downloader, it implements the Doer interface and downloads
// individual files.
type downloader struct {
	client *utils.APIClient
}

func (d *downloader) Do(file interface{}, ds *utils.DoerState) string {

	var hash string
	if f, isObject := file.(*vt.Object); isObject {
		hash = f.ID()
	} else {
		hash = file.(string)
	}

	ds.Progress = fmt.Sprintf("%s %4.1f%%", hash, 0.0)

	// Get download URL
	var downloadURL string
	_, err := d.client.GetData(vt.URL("files/%s/download_url", hash), &downloadURL)

	if err == nil {
		dstPath := path.Join(viper.GetString("output"), hash)
		err = downloadFile(d.client, downloadURL, dstPath, func(resp *grab.Response) {
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

// ZIP downloader, uses the API for creating ZIP files in the backend.
type zipDownloader struct {
	client *utils.APIClient
}

func (z *zipDownloader) Download(hashes utils.StringReader, password string) error {

	spin := spinner.New(spinner.CharSets[6], 250*time.Millisecond)
	spin.Color("green")
	spin.Suffix = " creating ZIP..."
	spin.Start()
	defer spin.Stop()

	hashList := make([]string, 0)
	for hash, err := hashes.ReadString(); err == nil; hash, err = hashes.ReadString() {
		hashList = append(hashList, hash)
	}

	req := struct {
		Hashes   []string `json:"hashes,omitempty"`
		Password string   `json:"password,omitempty"`
	}{
		Hashes:   hashList,
		Password: password,
	}

	resp, err := z.client.PostData(vt.URL("intelligence/zip_files"), &req)
	if err != nil {
		return err
	}

	var obj *vt.Object
	if err := json.Unmarshal(resp.Data, &obj); err != nil {
		return err
	}

	for obj.MustGetString("status") != "finished" {
		obj, err = z.client.GetObject(vt.URL("intelligence/zip_files/%s", obj.ID))
		if err != nil {
			return err
		}
		switch status, _ := obj.GetString("status"); status {
		case "error-starting":
			return errors.New("Error starting ZIP file creation")
		case "error-creating":
			return errors.New("Error creating ZIP file")
		case "timeout":
			return errors.New("ZIP file creation is taking too long")
		}
		progress, _ := obj.GetFloat64("progress")
		spin.Suffix = fmt.Sprintf(" creating ZIP... %2.0f%%", progress*100)
		time.Sleep(2 * time.Second)
	}

	url := vt.URL("intelligence/zip_files/%s/download", obj.ID())
	dstPath := viper.GetString("output")

	err = downloadFile(z.client, url.String(), dstPath, func(resp *grab.Response) {
		spin.Suffix = fmt.Sprintf(
			" downloading ZIP %4.1f%% %6.1f KBi/s",
			resp.Progress()*100, resp.BytesPerSecond()/1024)
	})

	return err
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
			re, _ := regexp.Compile(`^([[:xdigit:]]{64}|[[:xdigit:]]{40}|[[:xdigit:]]{32})$`)
			hashes := utils.NewFilteredStringReader(argReader, re)
			if viper.GetBool("zip") {
				z := zipDownloader{client}
				err = z.Download(hashes, viper.GetString("zip-password"))
			} else {
				c := utils.NewCoordinator(viper.GetInt("threads"))
				c.DoWithStringsFromReader(&downloader{client}, hashes)
			}
			return err
		},
	}

	cmd.Flags().BoolP("zip", "z", false, "download in a ZIP file")
	cmd.Flags().String("zip-password", "", "password for the ZIP file, used with --zip")

	addThreadsFlag(cmd.Flags())
	addOutputFlag(cmd.Flags())

	return cmd
}
