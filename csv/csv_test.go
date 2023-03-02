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
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

type Case struct {
	data     interface{}
	expected string
}

var csvTests = []Case{
	{
		data:     nil,
		expected: "null",
	},
	{
		data:     []int{1, 2, 3},
		expected: "1\n2\n3\n",
	},
	{
		data: map[string]interface{}{
			"b": []int{1, 2},
			"a": 2,
			"c": nil,
		},
		expected: "a,b,c\n2,\"1,2\",null\n",
	},
}

func TestCSV(t *testing.T) {
	for _, test := range csvTests {
		b := new(bytes.Buffer)
		err := NewEncoder(b).Encode(test.data)
		assert.NoError(t, err)
		assert.Equal(t, test.expected, b.String(), "Test %v", test.data)
	}
}
