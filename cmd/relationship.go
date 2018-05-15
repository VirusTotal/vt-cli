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
	"encoding/gob"
	"fmt"
	"os"
	"path"

	"github.com/VirusTotal/vt-go/vt"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

var objectRelationshipsMap map[string][]vt.RelationshipMeta

func init() {
	home, _ := homedir.Dir()
	f, err := os.Open(path.Join(home, ".vt.relationships.cache"))
	if err == nil {
		defer f.Close()
		dec := gob.NewDecoder(f)
		dec.Decode(&objectRelationshipsMap)
	}
}

func NewRelationshipCmd(collection, relationship, use, description string) *cobra.Command {
	cmd := &cobra.Command{
		Args:  cobra.ExactArgs(1),
		Use:   fmt.Sprintf("%s %s", relationship, use),
		Short: description,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := NewObjectPrinter()
			if err != nil {
				return err
			}
			return p.PrintCollection(vt.URL("%s/%s/%s", collection, args[0], relationship))
		},
	}

	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())
	addLimitFlag(cmd.Flags())
	addCursorFlag(cmd.Flags())

	return cmd
}

func addRelationshipCmds(cmd *cobra.Command, collection, objectType, use string) {
	relationships := objectRelationshipsMap[objectType]
	for _, r := range relationships {
		cmd.AddCommand(NewRelationshipCmd(collection, r.Name, use, r.Description))
	}
}
