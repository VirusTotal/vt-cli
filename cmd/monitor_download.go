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
	"path"
	"strings"

	"github.com/VirusTotal/vt-cli/utils"
	vt "github.com/VirusTotal/vt-go"
	"github.com/cavaliercoder/grab"
	"github.com/fatih/color"
	"github.com/spf13/viper"
)

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
