package csv

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

func flatten(i interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	err := flattenValue(reflect.ValueOf(i), "", result)
	return result, err
}

func flattenValue(v reflect.Value, prefix string, m map[string]interface{}) error {
	switch v.Kind() {
	case reflect.Map:
		return flattenMap(v, prefix, m)
	case reflect.Struct:
		return flattenStruct(v, prefix, m)
	case reflect.Slice:
		return flattenSlice(v, prefix, m)
	case reflect.Interface, reflect.Ptr:
		if v.IsNil() {
			m[prefix] = "null"
		} else {
			return flattenValue(v.Elem(), prefix, m)
		}
	default:
		m[prefix] = v.Interface()
	}
	return nil
}

func flattenSlice(v reflect.Value, prefix string, m map[string]interface{}) error {
	n := v.Len()
	if n == 0 {
		return nil
	}

	first := v.Index(0)
	if first.Kind() == reflect.Interface {
		if !first.IsNil() {
			first = first.Elem()
		}
	}

	switch first.Kind() {
	case reflect.Map, reflect.Slice, reflect.Struct:
		// Add the JSON representation of lists with complex types.
		// Otherwise the number of CSV headers can grow significantly.
		b, err := json.Marshal(v.Interface())
		if err != nil {
			return err
		}
		m[prefix] = string(b)
	default:
		values := make([]string, v.Len())
		for i := 0; i < v.Len(); i++ {
			val := v.Index(i).Interface()
			if val == nil {
				values[i] = "null"
			} else {
				values[i] = fmt.Sprintf("%v", val)
			}
		}
		m[prefix] = strings.Join(values, ",")
	}
	return nil
}

func flattenStruct(v reflect.Value, prefix string, m map[string]interface{}) (err error) {
	n := v.NumField()
	if prefix != "" {
		prefix += "/"
	}
	for i := 0; i < n; i++ {
		typeField := v.Type().Field(i)
		key := typeField.Tag.Get("csv")
		if key == "" {
			key = v.Type().Field(i).Name
		}
		if err = flattenValue(v.Field(i), prefix+key, m); err != nil {
			return err
		}
	}
	return err
}

func flattenMap(v reflect.Value, prefix string, m map[string]interface{}) (err error) {
	if prefix != "" {
		prefix += "/"
	}
	for _, k := range v.MapKeys() {
		if err := flattenValue(v.MapIndex(k), fmt.Sprintf("%v%v", prefix, k.Interface()), m); err != nil {
			return err
		}
	}
	return nil
}
