// Copyright © 2019 The VirusTotal CLI authors. All Rights Reserved.
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
	"bufio"
	"io"
	"os"
	"regexp"
	"strings"
)

// StringReader is the interface that wraps the ReadString method.
type StringReader interface {
	ReadString() (string, error)
}

// StringArrayReader is a wrapper around a slice of strings that implements
// the StringReader interface. Each time the ReadString method is called a
// string from the array is returned and the position is advanced by one. When
// all strings have been returned ReadString returns an io.EOF error.
type StringArrayReader struct {
	strings []string
	pos     int
}

// NewStringArrayReader creates a new StringArrayReader.
func NewStringArrayReader(strings []string) *StringArrayReader {
	return &StringArrayReader{strings: strings}
}

// ReadString reads one string from StringArrayReader. When all strings have
// been returned ReadString returns an io.EOF error.
func (sar *StringArrayReader) ReadString() (string, error) {
	if sar.pos == len(sar.strings) {
		return "", io.EOF
	}
	s := sar.strings[sar.pos]
	sar.pos++
	return s, nil
}

// StringIOReader is a wrapper around a bufio.Scanner that implements the
// StringReader interface.
type StringIOReader struct {
	scanner *bufio.Scanner
}

// NewStringIOReader creates a new StringIOReader.
func NewStringIOReader(r io.Reader) *StringIOReader {
	return &StringIOReader{scanner: bufio.NewScanner(r)}
}

// ReadString reads one string from StringIOReader. When all strings have
// been returned ReadString returns an io.EOF error.
func (sir *StringIOReader) ReadString() (string, error) {
	for sir.scanner.Scan() {
		s := strings.TrimSpace(sir.scanner.Text())
		if s != "" {
			return s, nil
		}
	}
	return "", io.EOF
}

// FilteredStringReader filters a StringReader returning only the strings that
// match a given regular expression.
type FilteredStringReader struct {
	r  StringReader
	re *regexp.Regexp
}

// NewFilteredStringReader creates a new FilteredStringReader that reads strings
// from r and return only those that match re.
func NewFilteredStringReader(r StringReader, re *regexp.Regexp) *FilteredStringReader {
	return &FilteredStringReader{r: r, re: re}
}

// ReadString reads strings from the underlying StringReader and returns the
// first one that matches the regular expression specified while creating the
// FilteredStringReader. If no more strings can be read err is io.EOF.
func (f *FilteredStringReader) ReadString() (s string, err error) {
	for s, err = f.r.ReadString(); s != "" || err == nil; s, err = f.r.ReadString() {
		if f.re.MatchString(s) {
			return s, err
		}
	}
	return s, err
}

// MappedStringReader reads strings from a StringReader and call a map function
// that transforms the strings in some other string.
type MappedStringReader struct {
	r     StringReader
	mapFn func(string) string
}

// NewMappedStringReader creates a new MappedStringReader that reads strings from
// r and can call mapFn for transforming the string before returning it.
func NewMappedStringReader(r StringReader, mapFn func(string) string) *MappedStringReader {
	return &MappedStringReader{r: r, mapFn: mapFn}
}

// ReadString reads strings from the underlying StringReader and can call the
// map function associated to the MappedStringReader with that string, then
// returns the result produced by the map function.
func (m *MappedStringReader) ReadString() (s string, err error) {
	if s, err = m.r.ReadString(); err == nil {
		return m.mapFn(s), nil
	}
	return s, err
}

// StringReaderFromCmdArgs returns a string reader for reading the arguments
// passed in the command line. If the arguments consists in single hypen "-",
// they are read from stdin.
func StringReaderFromCmdArgs(args []string) StringReader {
	if len(args) == 1 && args[0] == "-" {
		return NewStringIOReader(os.Stdin)
	} else {
		return NewStringArrayReader(args)
	}
}
