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
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	glob "github.com/gobwas/glob"
)

// Colors is a structure passed to NewEncoder for specifying the colors used
// for printing keys, values and comments in the resulting YAML.
type Colors struct {
	KeyColor     *color.Color
	ValueColor   *color.Color
	CommentColor *color.Color
}

// An Encoder writes values as YAML to an output stream.
type Encoder struct {
	w              io.Writer
	keyPrinter     func(w io.Writer, format string, a ...interface{})
	commentPrinter func(w io.Writer, format string, a ...interface{})

	// List of globs that define the keys whose values should be encoded as a
	// date. Every key that matches any of the globs are considered a key if
	// they are a number.
	dateKeys []glob.Glob

	Colors     *Colors
	indentSize int
}

// EncoderOption represents an option for creating a new encoder.
type EncoderOption func(*Encoder)

// EncoderColors sets the colors for highlighting keys, values and comments.
func EncoderColors(c *Colors) EncoderOption {
	return func(e *Encoder) { e.Colors = c }
}

// EncoderDateKeys sets a list of globs that define the keys whose values
// should be encoded as a date. Every key that matches any of the globs and
// have a numeric value are encoded as a date, which means that a comment is
// added with the human-friendly date.
func EncoderDateKeys(g []glob.Glob) EncoderOption {
	return func(e *Encoder) { e.dateKeys = g }
}

// EncoderIndent sets the indentation size used while encoding the YAML.
func EncoderIndent(i int) EncoderOption {
	return func(e *Encoder) { e.indentSize = i }
}

// NewEncoder returns a new YAML encoder that writes to w.
func NewEncoder(w io.Writer, options ...EncoderOption) *Encoder {
	enc := &Encoder{w: w, indentSize: 2}
	for _, opt := range options {
		opt(enc)
	}
	if enc.Colors == nil {
		enc.Colors = &Colors{
			KeyColor:     color.New(),
			ValueColor:   color.New(),
			CommentColor: color.New(),
		}
	}
	return enc
}

// lineBreakV decides whether or not a line break should be written based in
// the type of v. It returns an indentation increment, a boolean indicating if
// a line break was actually written and an error.
func (enc *Encoder) lineBreakV(v reflect.Value, indent int) (int, error) {
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return 0, nil
		}
		return enc.lineBreakV(v.Elem(), indent)
	case reflect.Map:
		if v.Len() > 0 {
			return enc.indentSize, enc.lineBreak(indent + enc.indentSize)
		}
	case reflect.Slice:
		if v.Len() > 0 {
			return 0, enc.lineBreak(indent)
		}
	}
	return 0, nil
}

// lineBreak writes a line break into the encoder's writer, followed by
// the number of indention characters specified by indent.
func (enc *Encoder) lineBreak(indent int) error {
	_, err := fmt.Fprintf(enc.w, "\n%s", strings.Repeat(" ", indent))
	return err
}

func (enc *Encoder) matchDateKey(key string) bool {
	for _, glob := range enc.dateKeys {
		if glob.Match(key) {
			return true
		}
	}
	return false
}

func (enc *Encoder) encodeMap(m reflect.Value, indent int, prefix string) (err error) {

	keyPrinter := enc.Colors.KeyColor.FprintfFunc()
	commentPrinter := enc.Colors.CommentColor.FprintfFunc()

	keys := keyList(m.MapKeys())
	sort.Sort(keys)
	n := len(keys)

	if prefix != "" {
		prefix += "."
	}

	var indentIncr int

	for i, k := range keys {
		keyPrinter(enc.w, "%s: ", k)
		v := m.MapIndex(k)
		if indentIncr, err = enc.lineBreakV(v, indent); err != nil {
			return err
		}
		if err = enc.encodeValue(v, indent+indentIncr, prefix+k.String()); err != nil {
			return err
		}
		switch v.Kind() {
		case reflect.Interface:
			v = v.Elem()
		case reflect.Ptr:
			v = v.Elem()
		}
		if v.IsValid() {
			vt := v.Type()
			ks := k.String()
			// If key is "date" or ends with "_date" and value is json.Number, this
			// field is a date.
			isDate := enc.matchDateKey(ks) &&
				vt.Name() == "Number" &&
				vt.PkgPath() == "encoding/json"
			// If this field is a date let's add a comment with the date in a
			// human-readable format.
			if isDate {
				ts, err := strconv.ParseInt(v.String(), 10, 64)
				if err != nil {
					panic(err)
				}
				commentPrinter(enc.w, "  # %v", time.Unix(ts, 0))
			}
		}
		if i < n-1 {
			err = enc.lineBreak(indent)
		}
		if err != nil {
			return err
		}
	}

	return err
}

// encodeValue writes the YAML encoding of v.
func (enc *Encoder) encodeValue(v reflect.Value, indent int, prefix string) (err error) {

	switch v.Kind() {
	case reflect.Map:
		return enc.encodeMap(v, indent, prefix)
	case reflect.Struct:
		m := make(map[string]interface{})
		n := v.NumField()
		for i := 0; i < n; i++ {
			typeField := v.Type().Field(i)
			key := typeField.Tag.Get("yaml")
			if key == "" {
				key = typeField.Name
			}
			m[key] = v.Field(i).Interface()
		}
		return enc.encodeMap(reflect.ValueOf(m), indent, prefix)
	case reflect.Slice:
		n := v.Len()
		if n == 0 {
			fmt.Fprint(enc.w, "[]")
		}
		for i := 0; i < n; i++ {
			_, err = fmt.Fprint(enc.w, "- ")
			if err == nil {
				err = enc.encodeValue(v.Index(i), 2+indent, prefix)
			}
			if err == nil && i < n-1 {
				err = enc.lineBreak(indent)
			}
			if err != nil {
				return err
			}
		}
	case reflect.Interface, reflect.Ptr:
		if v.IsNil() {
			_, err = fmt.Fprintf(enc.w, "null")
		} else {
			err = enc.encodeValue(v.Elem(), indent, prefix)
		}
	case reflect.String:
		s := v.String()
		t := v.Type()
		switch {
		case t.PkgPath() == "encoding/json" && t.Name() == "Number":
			// This string is a actually a json.Number.
			_, err = enc.Colors.ValueColor.Fprintf(enc.w, "%s", s)
		case strings.Contains(s, "\n"):
			// If string contains new line characters lets encode it as a
			// literal block. Example:
			// literal_block : |
			//   Lorem ipsum dolor sit amet consectetur
			//   adipiscing elit potenti, ante taciti montes
			//   risus mollis
			enc.Colors.ValueColor.Fprint(enc.w, "|")
			for _, line := range strings.Split(s, "\n") {
				enc.lineBreak(2 + indent)
				enc.Colors.ValueColor.Fprintf(enc.w, "%s", line)
			}
		default:
			_, err = enc.Colors.ValueColor.Fprintf(enc.w, "%#v", v)
		}
	default:
		_, err = enc.Colors.ValueColor.Fprintf(enc.w, "%#v", v)
	}

	return err
}

// Encode writes the YAML encoding of v to the stream.
func (enc *Encoder) Encode(v interface{}) error {
	if err := enc.encodeValue(reflect.ValueOf(v), 0, ""); err != nil {
		return err
	}
	return enc.lineBreak(0)
}
