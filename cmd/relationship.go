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
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"os"
	"path"

	vt "github.com/VirusTotal/vt-go"
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
			client, err := NewAPIClient()
			if err != nil {
				return err
			}
			objectID := args[0]
			if collection == "urls" {
				// If collections is "urls" let's encode the objectID is the
				// URL itself and it needs to be encoded in base64.
				objectID = base64.RawURLEncoding.EncodeToString([]byte(objectID))
			}
			url := vt.URL("%s/%s/%s", collection, objectID, relationship)
			// A relationship can return a single object or a collection, so
			// we retrieve the data but do not unmarshall it as we don't know
			// the kind of data that we are receiving.
			var data json.RawMessage
			if _, err = client.GetData(url, &data); err != nil {
				return err
			}
			p, err := NewObjectPrinter(cmd)
			if err != nil {
				return err
			}
			obj := &vt.Object{}
			// Try to unmarshall the data into an object, if it succeeds we
			// can proceed to print the object, if not the relationship returns
			// a collection.
			if err := json.Unmarshal(data, obj); err == nil {
				return p.PrintObject(obj)
			}
			// If the returned data was not an object let's use PrintCollection.
			// This is not the most efficient solution as it sends another
			// request to the server.
			// TODO(vmalvarez): Avoid the extra API request by reusing the data
			// that we already have.
			return p.PrintCollection(url)
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
