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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// NewFileDirReader reads all files from the given directory `fileDir`.
// It can optionally traverse subdirectories if `recursive` is true,
// and will limit recursion to `maxDepth` levels if specified.
//
// Uses the standard library's `filepath.WalkDir` to traverse directories efficiently,
// and `fs.SkipDir` to skip directories when recursion is disabled or maxDepth is reached.
func NewFileDirReader(fileDir string, recursive bool, maxDepth int) (*StringArrayReader, error) {
	var filePaths []string
	rootDepth := pathDepth(fileDir)

	// filePaths is safely appended within WalkDir because WalkDir executes the callback sequentially.
	// No race conditions occur in this implementation, even with slice reallocation.
	err := filepath.WalkDir(fileDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			filePaths = append(filePaths, path)
			return nil
		}

		currentDepth := pathDepth(path) - rootDepth
		// we skip directory if recursive is disabled or
		// if we reached configured maxDepth
		if !recursive && path != fileDir ||
			currentDepth >= maxDepth {
			return fs.SkipDir
		}

		return nil
	})

	if err != nil {
		return nil, err
	}
	return &StringArrayReader{strings: filePaths}, nil
}

// pathDepth returns the depth of a given path by counting its components.
// It uses filepath.Separator, which ensures correct behavior across all platforms
// (Windows, macOS, Linux), regardless of the underlying path separator.
func pathDepth(path string) int {
	return len(strings.Split(filepath.Clean(path), string(filepath.Separator)))
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
