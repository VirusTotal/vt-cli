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
package utils_test

import (
	"reflect"
	"testing"

	"github.com/VirusTotal/vt-cli/utils"
)

var testMap = map[string]interface{}{
	"foo": map[string]interface{}{
		"qux": map[string]interface{}{
			"quux": map[string]interface{}{
				"key1": "val1",
				"key2": "val2",
				"key3": []string{"val3"},
			},
		},
	},
	"bar": map[string]interface{}{
		"corge": map[string]interface{}{
			"key2": "val2",
		},
	},
	"baz": map[string]interface{}{
		"key3": "val3",
	},
	"qux": []interface{}{
		map[string]interface{}{
			"key4": "val4",
		},
		map[string]interface{}{
			"key5": "val5",
		},
	},
	"ary": []string{"1", "3"},
}

type testCase struct {
	include []string
	exclude []string
	input   map[string]interface{}
	output  map[string]interface{}
}

var testCases = []testCase{

	testCase{
		include: []string{"foo**"},
		input:   testMap,
		output: map[string]interface{}{
			"foo": map[string]interface{}{
				"qux": map[string]interface{}{
					"quux": map[string]interface{}{
						"key1": "val1",
						"key2": "val2",
						"key3": []string{"val3"},
					},
				},
			},
		},
	},

	testCase{
		include: []string{"foo"},
		exclude: []string{"**.quux"},
		input:   testMap,
		output: map[string]interface{}{

		},
	},

	testCase{
		include: []string{"foo**"},
		exclude: []string{"**.key1"},
		input:   testMap,
		output: map[string]interface{}{
			"foo": map[string]interface{}{
				"qux": map[string]interface{}{
					"quux": map[string]interface{}{
						"key2": "val2",
						"key3": []string{"val3"},
					},
				},
			},
		},
	},

	testCase{
		include: []string{"foo**"},
		exclude: []string{"**.key1"},
		input:   testMap,
		output: map[string]interface{}{
			"foo": map[string]interface{}{
				"qux": map[string]interface{}{
					"quux": map[string]interface{}{
						"key2": "val2",
						"key3": []string{"val3"},
					},
				},
			},
		},
	},

	testCase{
		include: []string{"foo.qux.**"},
		input:   testMap,
		output: map[string]interface{}{
			"foo": map[string]interface{}{
				"qux": map[string]interface{}{
					"quux": map[string]interface{}{
						"key1": "val1",
						"key2": "val2",
						"key3": []string{"val3"},
					},
				},
			},
		},
	},

	testCase{
		include: []string{"foo.qux.quux.key*"},
		input:   testMap,
		output: map[string]interface{}{
			"foo": map[string]interface{}{
				"qux": map[string]interface{}{
					"quux": map[string]interface{}{
						"key1": "val1",
						"key2": "val2",
						"key3": []string{"val3"},
					},
				},
			},
		},
	},

	testCase{
		include: []string{"foo.qux.quux.key2"},
		input:   testMap,
		output: map[string]interface{}{
			"foo": map[string]interface{}{
				"qux": map[string]interface{}{
					"quux": map[string]interface{}{
						"key2": "val2",
					},
				},
			},
		},
	},

	testCase{
		include: []string{"ba**"},
		exclude: []string{"baz**"},
		input:   testMap,
		output: map[string]interface{}{
			"bar": map[string]interface{}{
				"corge": map[string]interface{}{
					"key2": "val2",
				},
			},
		},
	},

	testCase{
		include: []string{"**.key2"},
		input:   testMap,
		output: map[string]interface{}{
			"foo": map[string]interface{}{
				"qux": map[string]interface{}{
					"quux": map[string]interface{}{
						"key2": "val2",
					},
				},
			},
			"bar": map[string]interface{}{
				"corge": map[string]interface{}{
					"key2": "val2",
				},
			},
		},
	},

	testCase{
		include: []string{"**.key5"},
		input:   testMap,
		output: map[string]interface{}{
			"qux": []interface{}{
				map[string]interface{}{
					"key5": "val5",
				},
			},
		},
	},

	testCase{
		include: []string{"qux"},
		input:   testMap,
		output: map[string]interface{}{
			"qux": []interface{}{
				map[string]interface{}{
					"key4": "val4",
				},
				map[string]interface{}{
					"key5": "val5",
				},
			},
		},
	},

	testCase{
		include: []string{"ary"},
		input:   testMap,
		output: map[string]interface{}{
			"ary": []string{"1", "3"},
		},
	},
}

func TestFilterMap(t *testing.T) {
	for _, tc := range testCases {
		r := utils.FilterMap(tc.input, tc.include, tc.exclude)
		eq := reflect.DeepEqual(r, tc.output)
		if !eq {
			t.Errorf(
				"Test failed with filter \"%s\".\n\nExpecting: %v\n\nGot: %v\n",
				tc.include, tc.output, r)
		}
	}
}
