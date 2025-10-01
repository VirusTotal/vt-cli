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
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/VirusTotal/vt-cli/utils"
	vt "github.com/VirusTotal/vt-go"
	grab "github.com/cavaliergopher/grab/v3"
	"github.com/fatih/color"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var base64RegExp = `^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`

var monitorItemsCmdExample = `  vt monitor list
  vt monitor list --filter "path:/myfolder/" --include path
  vt monitor list --filter "tag:detected" --include path,last_analysis_results.*.result,last_detections_count`

// NewMonitorItemsListCmd returns a list or monitor_items according to a filter.
func NewMonitorItemsListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List monitor in your account",
		Example: monitorItemsCmdExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.PrintCollection(vt.URL("monitor/items"))
		},
	}

	addIncludeExcludeFlags(cmd.Flags())
	addFilterFlag(cmd.Flags())
	addLimitFlag(cmd.Flags())
	addCursorFlag(cmd.Flags())

	return cmd
}

// Monitor downloader, it implements the Doer interface. Retrieves the item
// path to know the destination filename and downloads and save each individual
// file using fileDownloader.DownloadFile
type monitorDownloader struct {
	fileDownloader
}

func (d *monitorDownloader) Do(file interface{}, ds *utils.DoerState) string {
	var monitorItemID string
	if f, isObject := file.(*vt.Object); isObject {
		monitorItemID = f.ID()
	} else {
		monitorItemID = file.(string)
	}

	// Resolve MonitorItemID to path
	ds.Progress = fmt.Sprintf("%s [resolving path]", monitorItemID)
	var obj *vt.Object
	obj, err := d.client.GetObject(vt.URL("monitor/items/%s", monitorItemID))
	if err != nil {
		return fmt.Sprintf("%s [%s]", monitorItemID, color.RedString(err.Error()))
	}

	monitorPath, err := obj.GetString("path")
	if err != nil {
		return fmt.Sprintf("%s [%s]", monitorItemID, color.RedString(err.Error()))
	}

	monitorPath = strings.TrimPrefix(monitorPath, "/")

	// From now progress shows the path instead of monitorItemID
	ds.Progress = fmt.Sprintf("%s %4.1f%%", monitorPath, 0.0)

	// Get download URL
	var downloadURL string
	_, err = d.client.GetData(vt.URL("monitor/items/%s/download_url", monitorItemID), &downloadURL)

	if err == nil {
		dstPath := path.Join(viper.GetString("output"), monitorPath)
		err = d.DownloadFile(downloadURL, dstPath, func(resp *grab.Response) {
			progress := 100 * resp.Progress()
			if progress < 100 {
				ds.Progress = fmt.Sprintf("%s %4.1f%% %6.1f KBi/s",
					monitorPath, progress, resp.BytesPerSecond()/1024)
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

	return fmt.Sprintf("%s [%s]", monitorPath, msg)
}

var monitorItemsDownloadCmdHelp = `Download files from your account.

This command download files in your monitor account using their MonitorItemID.`

var monitorItemsDownloadCmdExample = `  vt monitor download "MonitorItemID"
  vt monitor download "MonitorItemID1" "MonitorItemID2" ...
  cat list_of_monitor_ids | vt monitor download -`

// NewMonitorItemsDownloadCmd returns a command for downloading files from your
// monitor account.
func NewMonitorItemsDownloadCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "download [monitor_id]...",
		Short:   "Download files from your monitor account",
		Long:    monitorItemsDownloadCmdHelp,
		Example: monitorItemsDownloadCmdExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			var argReader utils.StringReader
			if len(args) == 0 {
				return errors.New("No item provided")
			} else if len(args) == 1 && args[0] == "-" {
				argReader = utils.NewStringIOReader(os.Stdin)
			} else {
				argReader = utils.NewStringArrayReader(args)
			}
			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			re, _ := regexp.Compile(base64RegExp)
			monitorItemIDs := utils.NewFilteredStringReader(argReader, re)

			c := utils.NewCoordinator(viper.GetInt("threads"))
			c.DoWithStringsFromReader(
				&monitorDownloader{fileDownloader: newFileDownloader(client)},
				monitorItemIDs)
			return err
		},
	}

	addThreadsFlag(cmd.Flags())
	addOutputFlag(cmd.Flags())
	return cmd
}

var monitorItemsSetDetailsCmdHelp = `Set details metadata for a file.

This command sets details metadata for a file in your monitor account
referenced by a MonitorItemID.`

var monitorItemsSetDetailsCmdExample = `  vt monitor setdetails "MonitorItemID" "Some file metadata."
  cat multiline_details | vt monitor setdetails "MonitorItemID"`

// NewMonitorItemsSetDetailsCmd returns a command for configuring item details.
func NewMonitorItemsSetDetailsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "setdetails [monitor_id] [details_string]",
		Short:   "Sets details metadata for a monitor file",
		Long:    monitorItemsSetDetailsCmdHelp,
		Example: monitorItemsSetDetailsCmdExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			var monitorItemID, details string
			if len(args) == 0 {
				return errors.New("No item provided")
			} else if len(args) == 1 {
				detailsBytes, err := io.ReadAll(os.Stdin)
				details = string(detailsBytes)
				if err != nil {
					return err
				}
			} else {
				details = args[1]
			}
			monitorItemID = args[0]

			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			re, _ := regexp.Compile(base64RegExp)
			if !re.MatchString(monitorItemID) {
				return errors.New("Bad MonitorItemID")
			}

			obj := vt.NewObjectWithID("monitor_item", monitorItemID)
			obj.Set("details", details)
			return client.PatchObject(
				vt.URL("monitor/items/%s/config", monitorItemID), obj)
		},
	}

	return cmd
}

var monitorItemsDeleteDetailsCmdHelp = `Delete details metadata from files.

This command delete details metadata from a file or files in your monitor
account that was previously set.`

// NewMonitorItemsDeleteDetailsCmd returns a command for removing item details.
func NewMonitorItemsDeleteDetailsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deletedetails [monitor_id]...",
		Short: "Delete details metadata from files",
		Long:  monitorItemsDeleteDetailsCmdHelp,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("No item provided")
			}

			client, err := NewAPIClient()
			if err != nil {
				return err
			}

			var waitGroup sync.WaitGroup
			for _, arg := range args {
				waitGroup.Add(1)
				go func(monitorItemID string) {
					url := vt.URL("monitor/items/%s/config", monitorItemID)
					obj := vt.NewObjectWithID("monitor_item", monitorItemID)
					obj.Set("details", nil)

					if err := client.PatchObject(url, obj); err != nil {
						fmt.Fprintf(os.Stderr, "%v\n", err)
					}
					waitGroup.Done()
				}(arg)
			}
			waitGroup.Wait()
			return nil
		},
	}
	return cmd
}

var monitorItemsDeleteCmdHelp = `Delete files in your account.

This command deletes files in your monitor account using a MonitorItemID,
deleting a folder recursivelly deletes all files and folders inside it.`

// NewMonitorItemsDeleteCmd returns a command for deleting files in your monitor
// account.
func NewMonitorItemsDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete [monitor_id]...",
		Short: "Delete monitor files",
		Long:  monitorItemsDeleteCmdHelp,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("No item provided")
			}

			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			var waitGroup sync.WaitGroup
			for _, arg := range args {
				waitGroup.Add(1)
				go func(monitorItemID string) {
					url := vt.URL("monitor/items/%s", monitorItemID)
					if _, err := client.Delete(url); err != nil {
						fmt.Fprintf(os.Stderr, "%v\n", err)
					}
					waitGroup.Done()
				}(arg)
			}
			waitGroup.Wait()
			return err
		},
	}

	return cmd
}

// MonitorFileUpload doer

type monitorFileUpload struct {
	uploader *vt.MonitorUploader
}

type uploadParams struct {
	filePath   string
	remotePath string
}

func (s *monitorFileUpload) Do(file interface{}, ds *utils.DoerState) string {
	params := file.(uploadParams)

	progressCh := make(chan float32)
	defer close(progressCh)

	go func() {
		for progress := range progressCh {
			if progress < 100 {
				ds.Progress = fmt.Sprintf("%s uploading... %4.1f%%", params.filePath, progress)
			} else {
				ds.Progress = fmt.Sprintf("%s done.", params.filePath)
			}
		}
	}()

	f, err := os.Open(params.filePath)
	if err != nil {
		return fmt.Sprintf("%s", err)
	}
	defer f.Close()

	item, err := s.uploader.Upload(f, params.remotePath, progressCh)
	if err != nil {
		return fmt.Sprintf("%s", err)
	}

	return fmt.Sprintf("%s %s", params.filePath, item.ID())
}

// runMonitorItemUpload exectutes the items upload, requesting verification from user
func runMonitorItemUpload(cmd *cobra.Command, args []string) error {
	localPath := args[0]
	remotePath := args[1]

	// Check if first arg is a file or a folder
	pathStat, err := os.Stat(localPath)
	if err != nil {
		return err
	}

	ch := make(chan interface{})

	switch mode := pathStat.Mode(); {
	case mode.IsDir():
		// Upload tree to remote
		localPathClean := strings.TrimRight(localPath, string(os.PathSeparator)) + string(os.PathSeparator)
		remotePathClean := strings.TrimRight(remotePath, "/") + "/"

		filesParams := make([]uploadParams, 0)
		filepath.Walk(
			localPathClean, func(path string, info os.FileInfo, err error) error {
				if !info.Mode().IsRegular() {
					return nil
				}
				relativePath := strings.SplitN(path, localPathClean, 2)[1]
				remoteAbsoluteFilename := remotePathClean + relativePath
				filesParams = append(filesParams, uploadParams{path, remoteAbsoluteFilename})
				return nil
			})

		// Confirm user want to create those files in remote
		fmt.Println("Following files are going to be created:")
		for _, params := range filesParams {
			fmt.Println(params.filePath + " -> " + params.remotePath)
		}
		var s string
		fmt.Println("Confirm(y/n)?")
		fmt.Scanln(&s)
		if s != "y" {
			return nil
		}

		go func() {
			for _, params := range filesParams {
				ch <- params
			}
			close(ch)
		}()

	case mode.IsRegular():
		// Upload only one file to remote
		go func() {
			params := uploadParams{localPath, remotePath}
			ch <- params
			close(ch)
		}()
	default:
		return errors.New("Not a regular file or folder")
	}

	client, err := NewAPIClient()
	if err != nil {
		return err
	}

	s := &monitorFileUpload{uploader: client.NewMonitorUploader()}
	c := utils.NewCoordinator(viper.GetInt("threads"))
	c.DoWithItemsFromChannel(s, ch)
	return nil
}

var monitorItemUploadCmdHelp = `Upload a file or files contained in a folder.

This command receives one file or folder path and uploads them to your
VirusTotal Monitor account. It returns uploaded the file paths followed by their
corresponding monitor ID.
You can use the "vt monitor [monitor_id]" command for retrieving
information about the it.`

var monitorItemUploadCmdExample = `  vt monitor item upload foo.exe /remote_folder/foo.exe
  vt monitor item upload myfolder/ /another_remote_folder/`

// NewMonitorItemsUploadCmd returns a new instance of the 'mointor upload file' command.
func NewMonitorItemsUploadCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "upload [file/folder] [remote_path]",
		Short:   "Upload one or more files to your account",
		Long:    monitorItemUploadCmdHelp,
		Example: monitorItemUploadCmdExample,
		Args:    cobra.ExactArgs(2),
		RunE:    runMonitorItemUpload,
	}
	addThreadsFlag(cmd.Flags())
	return cmd
}

var monitorCmdHelp = `Manage your VirusTotal Monitor account.

This command allows you to manage the contents of your account and retrieve
information about analyses performed to your collection.

Reference:
  https://docs.virustotal.com/reference/monitor`

// NewMonitorCmd returns a new instance of the 'monitor_item' command.
func NewMonitorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "monitor [monitor_id]...",
		Short: "Manage your monitor account",
		Long:  monitorCmdHelp,
		Args:  cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			re, _ := regexp.Compile(base64RegExp)
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.GetAndPrintObjects("monitor/items/%s",
				utils.StringReaderFromCmdArgs(args),
				re)
		},
	}

	addThreadsFlag(cmd.Flags())
	addIncludeExcludeFlags(cmd.Flags())

	cmd.AddCommand(NewMonitorItemsListCmd())
	cmd.AddCommand(NewMonitorItemsUploadCmd())
	cmd.AddCommand(NewMonitorItemsDeleteCmd())
	cmd.AddCommand(NewMonitorItemsDownloadCmd())
	cmd.AddCommand(NewMonitorItemsSetDetailsCmd())
	cmd.AddCommand(NewMonitorItemsDeleteDetailsCmd())

	addRelationshipCmds(cmd, "monitor/items", "monitor_item", "[monitor_id]", false)

	return cmd
}
