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
