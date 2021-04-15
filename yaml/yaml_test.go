// Copyright © 2017 VirusTotal CLI authors. All Rights Reserved.
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
package yaml

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/glob"

	"github.com/stretchr/testify/assert"
)

type T struct {
	data interface{}
	yaml string
}

func Y(s string) string {
	t := make([]string, 0)
	for _, l := range strings.Split(s, "\n") {
		if len(l) > 3 {
			t = append(t, strings.Replace(l[3:], "\t", " ", -1))
		}
	}
	return strings.Join(t, "\n") + "\n"
}

var tests = []T{
	{
		data: "foo",
		yaml: Y(`
			"foo"
		`),
	},
	{
		data: 1,
		yaml: Y(`
			1
		`),
	},
	{
		data: json.Number("1"),
		yaml: Y(`
			1
		`),
	},
	{
		data: json.Number("1.0"),
		yaml: Y(`
			1.0
		`),
	},
	{
		data: false,
		yaml: Y(`
			false
		`),
	},
	{
		data: true,
		yaml: Y(`
			true
		`),
	},
	{
		data: map[string]string{},
		yaml: Y(``),
	},
	{
		data: map[string]map[string]string{
			"foo": map[string]string{},
		},
		yaml: Y(`
			foo: `),
	},
	{
		data: []string{},
		yaml: Y(`
			[]`),
	},
	{
		data: map[string]string{
			"uno":  "1",
			"dos":  "2",
			"tres": "3",
			"": "",
			"#foo": "foo",
			"|foo": "foo",
			"_foo": "foo",
		},
		yaml: Y(`
			"": ""
			"#foo": "foo"
			_foo: "foo"
			"|foo": "foo"
			dos: "2"
			tres: "3"
			uno: "1"
			`),
	},
	{
		data: []string{
			"uno",
			"dos",
			"tres",
		},
		yaml: Y(`
			- "uno"
			- "dos"
			- "tres"
			`),
	},
	{
		data: struct {
			Foo string
			Bar string
		}{
			"uno",
			"dos",
		},
		// Struct fields are re-ordered alphabetically.
		yaml: Y(`
			Bar: "dos"
			Foo: "uno"
			`),
	},
	{
		data: struct {
			Foo string
		}{
			"uno\ndos",
		},
		yaml: Y(`
			Foo: |
			  uno
			  dos
			`),
	},
	{
		data: map[string]interface{}{
			"numbers": []interface{}{
				map[string]string{
					"number":  "1",
					"numeral": "first",
				},
				map[string]string{
					"number":  "2",
					"numeral": "second",
				},
			},
		},
		yaml: Y(`
			numbers:` + " " + `
			- number: "1"
			  numeral: "first"
			- number: "2"
			  numeral: "second"
			`),
	},
	{
		data: struct {
			Foo_date json.Number
		}{
			Foo_date: "10000",
		},
		yaml: Y(fmt.Sprintf(`
			Foo_date: 10000  # %v
			`,  time.Unix(10000, 0))),
	},
	{
		data: struct {
			Bar_date int64
		}{
			Bar_date: 10000,
		},
		yaml: Y(fmt.Sprintf(`
			Bar_date: 10000  # %v
			`,  time.Unix(10000, 0))),
	},
	{
		data: struct {
			Baz_date float64
		}{
			Baz_date: 1618312811,
		},
		yaml: Y(fmt.Sprintf(`
			Baz_date: 1.618312811e+09  # %v
			`,  time.Unix(1618312811, 0))),
	},
}

func TestYAML(t *testing.T) {

	var b bytes.Buffer

	for _, test := range tests {
		enc := NewEncoder(&b,
			EncoderIndent(1),
			EncoderDateKeys([]glob.Glob{
				glob.MustCompile("*_date"),
			}))
		assert.NoError(t, enc.Encode(test.data))
		assert.Equal(t, test.yaml, b.String(), "Test %v", test.data)
		b.Reset()
	}

	enc := NewEncoder(&b, EncoderIndent(1),
		EncoderDateKeys([]glob.Glob{
			glob.MustCompile("*_date"),
		}))
	assert.NoError(t, enc.Encode(tests[5].data))
	assert.Equal(t, tests[5].yaml, b.String())
}
