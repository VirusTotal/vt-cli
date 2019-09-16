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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/VirusTotal/vt-cli/utils"
	vt "github.com/VirusTotal/vt-go"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var base64RegExp = `^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`

// NewMonitorItemsListCmd returns a list or monitor_items according to a filter.
func NewMonitorItemsListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List monitor items in your account",

		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.PrintCollection(vt.URL("monitor/items"))
		},
	}

	addIncludeExcludeFlags(cmd.Flags())
	addFilterFlag(cmd.Flags(), "path:/")
	addLimitFlag(cmd.Flags())
	addCursorFlag(cmd.Flags())

	return cmd
}

// Upload files to Monitor

type monitorFileUpload struct {
	scanner *vt.FileScanner
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

	item, err := s.scanner.MonitorUploadFilename(f, params.remotePath, progressCh)
	if err != nil {
		return fmt.Sprintf("%s", err)
	}

	return fmt.Sprintf("%s %s", params.filePath, item.ID())
}

var monitorItemUploadCmdHelp = `Upload a file or files contained in a folder.

This command receives one file or folder path and uploads them to your
VirusTotal Monitor account. It returns uploaded the file paths followed by their
corresponding monitor ID.
You can use the "vt monitor items [monitor_id]" command for retrieving
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

		RunE: func(cmd *cobra.Command, args []string) error {
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
				localPathClean := strings.TrimRight(localPath, "/") + "/"
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
				panic("Not a regular file or folder")
			}

			client, err := NewAPIClient()
			if err != nil {
				return err
			}

			s := &monitorFileUpload{scanner: client.NewFileScanner()}
			c := utils.NewCoordinator(viper.GetInt("threads"))
			c.DoWithItemsFromChannel(s, ch)
			return nil
		},
	}
	addThreadsFlag(cmd.Flags())
	return cmd
}

var monitorItemsCmdExample = `  vt monitor items list
  vt monitor items list --filter "path:/myfolder/" --include path
  vt monitor items list --filter "tag:detected" --include path,last_analysis_results.*.result,last_detections_count`

// NewMonitorItemsCmd returns a new instance of the 'monitor_item' command.
func NewMonitorItemsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "items [monitor_id]...",
		Short:   "Manage monitor items",
		Example: monitorItemsCmdExample,
		Args:    cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			re, _ := regexp.Compile(base64RegExp)
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.GetAndPrintObjects("monitor/items", args, re)
		},
	}

	addThreadsFlag(cmd.Flags())

	cmd.AddCommand(NewMonitorItemsListCmd())
	cmd.AddCommand(NewMonitorItemsUploadCmd())

	addRelationshipCmds(cmd, "monitor/items", "monitor_item", "[monitor_id]")

	return cmd
}

var monitorCmdHelp = `Manage your VirusTotal Monitor account.

This command allows you to manage the contents of your account and retrieve
information about analyses performed to your collection.

Reference:
  https://developers.virustotal.com/v3.0/reference#monitor`

// NewMonitorCmd returns a new instance of the 'monitor' command.
func NewMonitorCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "monitor [subcommand]",
		Short: "Manage your monitor account",
		Long:  monitorCmdHelp,
	}

	cmd.AddCommand(NewMonitorItemsCmd())
	return cmd
}
