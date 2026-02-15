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

package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_NewFileDirReader(t *testing.T) {
	t.Parallel()

	useCases := []struct {
		name string

		directories []string
		files       []string
		recursive   bool
		maxDepth    int

		want func(string) *StringArrayReader
	}{

		{
			name:        "want get back empty files",
			directories: []string{},
			files:       []string{},
			recursive:   true,
			maxDepth:    2,
			want: func(d string) *StringArrayReader {
				return &StringArrayReader{
					strings: nil,
				}
			},
		},
		{
			name:        "want to read single file",
			directories: []string{},
			files:       []string{"z.txt"},
			recursive:   true,
			maxDepth:    2,
			want: func(d string) *StringArrayReader {
				return &StringArrayReader{
					strings: []string{
						filepath.Join(d, "z.txt"),
					},
				}
			},
		},
		{
			name:        "want read all files within all subdirectories",
			directories: []string{"sub", "sub/sub", ".hidden"},
			files:       []string{"a.txt", "b.txt", "sub/c.txt", "sub/sub/d.txt", ".hidden/config"},
			recursive:   true,
			maxDepth:    3,
			want: func(d string) *StringArrayReader {
				return &StringArrayReader{
					strings: []string{
						filepath.Join(d, ".hidden/config"),
						filepath.Join(d, "a.txt"),
						filepath.Join(d, "b.txt"),
						filepath.Join(d, "sub/c.txt"),
						filepath.Join(d, "sub/sub/d.txt"),
					},
				}
			},
		},
		{
			name:        "want to ignore all subdirectories",
			directories: []string{"sub", "sub/sub"},
			files:       []string{"a.txt", "b.txt", "sub/c.txt", "sub/sub/d.txt"},
			recursive:   false,
			maxDepth:    10,
			want: func(d string) *StringArrayReader {
				return &StringArrayReader{
					strings: []string{
						filepath.Join(d, "a.txt"),
						filepath.Join(d, "b.txt"),
					},
				}
			},
		},
		{
			name:        "want to read until first depth",
			directories: []string{"sub", "sub/sub"},
			files:       []string{"a.txt", "b.txt", "sub/c.txt", "sub/sub/d.txt"},
			recursive:   true,
			maxDepth:    1,
			want: func(d string) *StringArrayReader {
				return &StringArrayReader{
					strings: []string{
						filepath.Join(d, "a.txt"),
						filepath.Join(d, "b.txt"),
					},
				}
			},
		},
		{
			name:        "want to read until second depth",
			directories: []string{"sub", "sub/sub"},
			files:       []string{"a.txt", "b.txt", "sub/c.txt", "sub/sub/d.txt"},
			recursive:   true,
			maxDepth:    2,
			want: func(d string) *StringArrayReader {
				return &StringArrayReader{
					strings: []string{
						filepath.Join(d, "a.txt"),
						filepath.Join(d, "b.txt"),
						filepath.Join(d, "sub/c.txt"),
					},
				}
			},
		},
	}

	for _, uc := range useCases {
		t.Run(uc.name, func(t *testing.T) {

			// create a temp directory, and will clean up after test ends
			rootDir := t.TempDir()

			for _, d := range uc.directories {
				path := filepath.Join(rootDir, d)
				rwxPerm := os.FileMode(0755)
				if err := os.Mkdir(path, rwxPerm); err != nil {
					t.Fatalf("unexpected error while Mkdir %v", err)
				}
			}

			for _, f := range uc.files {
				path := filepath.Join(rootDir, f)
				rwPerm := os.FileMode(0644)
				if err := os.WriteFile(path, []byte("hello world!"), rwPerm); err != nil {
					t.Fatalf("unexpected error while WriteFile %v", err)
				}
			}

			got, err := NewFileDirReader(rootDir, uc.recursive, uc.maxDepth)
			if err != nil {
				t.Errorf("unexpected error while NewFileDirReader err:%v", err)
			}
			if diff := cmp.Diff(
				uc.want(rootDir),
				got,
				cmp.AllowUnexported(StringArrayReader{}),
			); diff != "" {
				t.Errorf("unexpected StringArrayReader mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_NewFileDirReader_Error(t *testing.T) {
	t.Parallel()

	rootDir := t.TempDir()
	noPerm := os.FileMode(0000)
	if err := os.WriteFile(filepath.Join(rootDir, "a.txt"), []byte("hello world!"), noPerm); err != nil {
		t.Fatalf("unexpected error while WriteFile %v", err)
	}
	path := filepath.Join(rootDir, "sub")
	if err := os.Mkdir(path, noPerm); err != nil {
		t.Fatalf("unexpected error while Mkdir %v", err)
	}
	_, err := NewFileDirReader(rootDir, false, 10)
	if err != nil {
		t.Errorf("unexpected error while NewFileDirReader err:%v", err)
	}
	_, err = NewFileDirReader(rootDir, true, 10)
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("unexpected error permissions denied message got:%v", err.Error())
	}
}

func Test_pathDepth(t *testing.T) {
	t.Parallel()

	useCases := []struct {
		name string
		dir  string
		want int
	}{
		{
			name: "want one depth when empty directory",
			want: 1,
		},
		{
			name: "want one depth when simple directory",
			dir:  "a",
			want: 1,
		},
		{
			name: "want 2 depth when sub directory",
			dir:  "a/a",
			want: 2,
		},
		{
			name: "want 3 depth when sub directory",
			dir:  "a-a/b_bb__/cccc/",
			want: 3,
		},
	}

	for _, uc := range useCases {
		t.Run(uc.name, func(t *testing.T) {
			if got, want := pathDepth(uc.dir), uc.want; got != want {
				t.Errorf("unexpected pathDepth, got:%v, want:%v", got, want)
			}
		})
	}
}
