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
	"fmt"
	"os"
	"path"
	"sync"

	"github.com/VirusTotal/vt-cli/utils"

	vt "github.com/VirusTotal/vt-go"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

func getRelatedObjects(collection, objectID, relationship string, limit int) ([]map[string]interface{}, error) {
	if collection == "urls" {
		// If collections is "urls" the objectID is the URL itself and
		// it needs to be encoded in base64.
		objectID = base64.RawURLEncoding.EncodeToString([]byte(objectID))
	}
	client, err := NewAPIClient()
	if err != nil {
		return nil, err
	}
	it, err := client.Iterator(
		vt.URL("%s/%s/%s", collection, objectID, relationship),
		vt.IteratorLimit(limit))
	if err != nil {
		return nil, err
	}
	defer it.Close()
	result := make([]map[string]interface{}, 0)
	for it.Next() {
		obj := it.Get()
		result = append(result, utils.ObjectToMap(obj))
	}
	if err := it.Error(); err != nil {
		return nil, err
	}
	return result, nil
}

// NewRelationshipCmd returns a new instance of the 'relationship' command.
func NewRelationshipCmd(collection, relationship, use, description string, private_flag bool) *cobra.Command {
	cmd := &cobra.Command{
		Args:  cobra.ExactArgs(1),
		Use:   fmt.Sprintf("%s %s", relationship, use),
		Short: description,
		RunE: func(cmd *cobra.Command, args []string) error {
			objectID := args[0]
			if collection == "urls" {
				// If collections is "urls" let's encode the objectID is the
				// URL itself and it needs to be encoded in base64.
				objectID = base64.RawURLEncoding.EncodeToString([]byte(objectID))
			}
			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			if viper.GetBool("private") {
				collection = "private/" + collection
			}
			url := vt.URL("%s/%s/%s", collection, objectID, relationship)
			return p.PrintCollection(url)
		},
	}

	addIncludeExcludeFlags(cmd.Flags())
	addIDOnlyFlag(cmd.Flags())
	addLimitFlag(cmd.Flags())
	addCursorFlag(cmd.Flags())

	if private_flag {
		addPrivateFlag(cmd.Flags())
	}

	return cmd
}

// NewRelationshipsCmd returns a new instance of the 'relationships' command.
func NewRelationshipsCmd(collection, objectType, use string, private_flag bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   fmt.Sprintf("relationships %s", use),
		Short: "Get all relationships.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var wg sync.WaitGroup
			var sm sync.Map
			if viper.GetBool("private") {
				objectType = "private_" + objectType
				collection = "private/" + collection
			}
			for _, r := range objectRelationshipsMap[objectType] {
				wg.Add(1)
				go func(relationshipName string) {
					objs, err := getRelatedObjects(
						collection,
						args[0],
						relationshipName,
						viper.GetInt("limit"))
					if err != nil {
						fmt.Println(err)
					} else if len(objs) > 0 {
						sm.Store(relationshipName, objs)
					}
					wg.Done()
				}(r.Name)
			}
			wg.Wait()

			m := make(map[string]interface{})
			sm.Range(func(key, value interface{}) bool {
				m[key.(string)] = value
				return true
			})

			if viper.IsSet("include") || viper.IsSet("exclude") {
				m = utils.FilterMap(m,
					viper.GetStringSlice("include"),
					viper.GetStringSlice("exclude"))
			}

			p, err := NewPrinter(cmd)
			if err != nil {
				return err
			}
			return p.Print(m)
		},
	}

	addIncludeExcludeFlags(cmd.Flags())
	addLimitFlag(cmd.Flags())

	if private_flag {
		addPrivateFlag(cmd.Flags())
	}

	return cmd
}

func addRelationshipCmds(cmd *cobra.Command, collection, objectType, use string, private_flag bool) {
	relationships := objectRelationshipsMap[objectType]
	for _, r := range relationships {
		cmd.AddCommand(NewRelationshipCmd(collection, r.Name, use, r.Description, private_flag))
	}
	cmd.AddCommand(NewRelationshipsCmd(collection, objectType, use, private_flag))
}
