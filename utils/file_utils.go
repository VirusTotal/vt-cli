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

package utils

import (
	"os"
	"path"
)

// FileDirReader returns all files inside a given directory
// as a StringArrayReader
func NewFileDirReader(fileDir string) (*StringArrayReader, error) {
	files, err := os.ReadDir(fileDir)
	if err != nil {
		return nil, err
	}
	fileNames := []string{}
	for _, f := range files {
		// Skip subdirectories
		if f.IsDir() {
			continue
		}
		fileNames = append(fileNames, path.Join(fileDir, f.Name()))
	}
	return &StringArrayReader{strings: fileNames}, nil
}

// IsDir function returns whether a file is a directory or not
func IsDir(f string) bool {
	fileInfo, err := os.Stat(f)
	if err != nil {
		// error reading the file, assuming it is not a directory
		return false
	}
	return fileInfo.IsDir()
}
