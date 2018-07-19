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

package utils

import (
	"reflect"

	glob "github.com/gobwas/glob"
)

// FilterMap receives a map with string keys and arbirary values (possibly
// other maps) and return a new map which is a subset of the original one
// contaning only the keys matching any of the patterns in "include" and
// excluding keys matching any of the patterns in "exclude". The logic for
// determining if a key matches the pattern goes as follow:
//
// * The path for the key is computed. If the key is in the top-level map its
//   path is the key itself, if the key is contained within a nested map its
//   path is the concatenation of the parent's path and the key, using a dot (.)
//   as a separator. The path for "key" in {a:{b:{key:val}}} is a.b.key.
//
// * The path is matched against the pattern, which can contain asterisks (*)
//   as a placeholder for any character different from a dot (.) and ** as a
//   placeholder for any character including a dot. For more information go to:
//   https://godoc.org/github.com/gobwas/glob#Compile
//
// * If the path matches any pattern in "include" the key is included in the
//   resulting map, as long as it doesn't match a pattern in "exclude".
//
func FilterMap(m map[string]interface{}, include, exclude []string) map[string]interface{} {
	includeGlob := make([]glob.Glob, len(include))
	excludeGlob := make([]glob.Glob, len(exclude))
	for i, p := range include {
		cp := glob.MustCompile(p, '.')
		includeGlob[i] = cp
	}
	for i, p := range exclude {
		cp := glob.MustCompile(p, '.')
		excludeGlob[i] = cp
	}
	filtered := filterMap(reflect.ValueOf(m), includeGlob, excludeGlob, "")
	return filtered.Interface().(map[string]interface{})
}

// actualValue returns v if it's not an interface. If v is an interface it
// returns the value pointed to by the interface.
func actualValue(v reflect.Value) reflect.Value {
	if v.Kind() == reflect.Interface {
		return v.Elem()
	}
	return v
}

// filterMap is the internal version of FilterMap.
func filterMap(m reflect.Value, include, exclude []glob.Glob, prefix string) reflect.Value {

	result := reflect.MakeMap(m.Type())

	for _, k := range m.MapKeys() {
		path := k.String()
		if prefix != "" {
			path = prefix + "." + path
		}
		match := false
		for _, p := range include {
			if p.Match(path) {
				match = true
				break
			}
		}
		for _, p := range exclude {
			if p.Match(path) {
				match = false
				break
			}
		}

		v := actualValue(m.MapIndex(k))

		switch v.Kind() {
		case reflect.Map:
			fm := filterMap(v, include, exclude, path)
			if fm.Len() > 0 {
				result.SetMapIndex(k, fm)
			}
		case reflect.Slice:
			s := reflect.MakeSlice(v.Type(), 0, v.Len())
			for i := 0; i < v.Len(); i++ {
				sliceItem := v.Index(i)
				if actualValue(sliceItem).Kind() == reflect.Map {
					fm := filterMap(actualValue(sliceItem), include, exclude, path)
					if fm.Len() > 0 {
						s = reflect.Append(s, fm)
					}
				} else if match {
					s = reflect.Append(s, sliceItem)
				}
			}
			if s.Len() > 0 {
				result.SetMapIndex(k, s)
			}
		default:
			if match {
				result.SetMapIndex(k, v)
			}
		}
	}

	return result
}
