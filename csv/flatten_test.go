package csv

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type T struct {
	data     interface{}
	expected map[string]interface{}
}

var tests = []T{
	{
		data:     "foo",
		expected: map[string]interface{}{"": "foo"},
	},
	{
		data:     1,
		expected: map[string]interface{}{"": 1},
	},
	{
		data:     false,
		expected: map[string]interface{}{"": false},
	},
	{
		data:     true,
		expected: map[string]interface{}{"": true},
	},
	{
		data:     map[string]string{},
		expected: map[string]interface{}{},
	},
	{
		data: map[string]map[string]string{
			"foo": {},
		},
		expected: map[string]interface{}{},
	},
	{
		data:     []string{},
		expected: map[string]interface{}{},
	},
	{
		data: map[string]string{
			"uno":  "1",
			"dos":  "2",
			"tres": "3",
			"":     "",
			"#foo": "foo",
			"|foo": "foo",
			"_foo": "foo",
		},
		expected: map[string]interface{}{
			"":     "",
			"uno":  "1",
			"dos":  "2",
			"tres": "3",
			"#foo": "foo",
			"|foo": "foo",
			"_foo": "foo",
		},
	},
	{
		data: []string{
			"uno",
			"dos",
			"tres",
		},
		expected: map[string]interface{}{"": "uno,dos,tres"},
	},
	{
		data: struct {
			Foo string
			Bar string
		}{
			"uno",
			"dos",
		},
		expected: map[string]interface{}{
			"Foo": "uno",
			"Bar": "dos",
		},
	},
	{
		data: struct {
			Foo string
		}{
			"uno\ndos",
		},
		expected: map[string]interface{}{"Foo": "uno\ndos"},
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
		expected: map[string]interface{}{
			"numbers": "[{\"number\":\"1\",\"numeral\":\"first\"},{\"number\":\"2\",\"numeral\":\"second\"}]",
		},
	},
	{
		data: struct {
			A map[string]string
			B map[string][]int
		}{
			A: map[string]string{"1": "xx", "2": "yy"},
			B: map[string][]int{"hello": {1, 2}},
		},
		expected: map[string]interface{}{
			"A/1":     "xx",
			"A/2":     "yy",
			"B/hello": "1,2",
		},
	},
	{
		data: map[string]interface{}{
			"key1": struct {
				A int
				B bool `csv:"field"`
				C []bool
			}{
				A: 2,
				B: true,
				C: []bool{true, false},
			},
			"key2": map[interface{}]interface{}{
				1:    []string{"hello", "world"},
				2:    []string{},
				true: "test",
				2.1: map[string]string{
					"x": "x",
					"y": "",
				},
			},
		},
		expected: map[string]interface{}{
			"key1/A":     2,
			"key1/field": true,
			"key1/C":     "true,false",
			"key2/1":     "hello,world",
			"key2/true":  "test",
			"key2/2.1/x": "x",
			"key2/2.1/y": "",
		},
	},
}

func TestFlatten(t *testing.T) {
	for _, test := range tests {
		result, err := flatten(test.data)
		assert.NoError(t, err)
		assert.Equal(t, test.expected, result, "Test %v", test.data)
	}
}
