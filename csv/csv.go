// Copyright © 2023 The VirusTotal CLI authors. All Rights Reserved.
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

package csv

import (
	"encoding/csv"
	"fmt"
	"io"
	"reflect"
	"sort"
)

// An Encoder writes values as CSV to an output stream.
type Encoder struct {
	w io.Writer
}

// NewEncoder returns a new CSV encoder that writes to w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

// Encode writes the CSV encoding of v to the stream.
func (enc *Encoder) Encode(v interface{}) error {
	if v == nil {
		_, err := enc.w.Write([]byte("null"))
		return err
	}

	var items []interface{}
	val := reflect.ValueOf(v)
	switch val.Kind() {
	case reflect.Slice:
		items = make([]interface{}, val.Len())
		for i := 0; i < val.Len(); i++ {
			items[i] = val.Index(i).Interface()
		}
	default:
		items = []interface{}{v}
	}
	numObjects := len(items)
	flattenObjects := make([]map[string]interface{}, numObjects)
	for i := 0; i < numObjects; i++ {
		f, err := flatten(items[i])
		if err != nil {
			return err
		}
		flattenObjects[i] = f
	}

	keys := make(map[string]struct{})
	for _, o := range flattenObjects {
		for k := range o {
			keys[k] = struct{}{}
		}
	}

	header := make([]string, len(keys))
	i := 0
	for k := range keys {
		header[i] = k
		i++
	}
	sort.Strings(header)

	w := csv.NewWriter(enc.w)
	if len(header) > 1 || len(header) == 0 && header[0] != "" {
		if err := w.Write(header); err != nil {
			return err
		}
	}

	for _, o := range flattenObjects {
		record := make([]string, len(keys))
		for i, key := range header {
			val, ok := o[key]
			if ok && val != nil {
				record[i] = fmt.Sprintf("%v", val)
			}
		}
		if err := w.Write(record); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
