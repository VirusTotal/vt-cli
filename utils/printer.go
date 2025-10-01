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
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/VirusTotal/vt-cli/csv"
	"github.com/VirusTotal/vt-cli/yaml"
	vt "github.com/VirusTotal/vt-go"
	"github.com/fatih/color"
	glob "github.com/gobwas/glob"
	ansi "github.com/k0kubun/go-ansi"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Printer prints objects to stdout.
type Printer struct {
	client *APIClient
	colors *yaml.Colors
	cmd    *cobra.Command
}

// NewPrinter creates a new object printer.
func NewPrinter(client *APIClient, cmd *cobra.Command, colors *yaml.Colors) (*Printer, error) {
	return &Printer{client: client, cmd: cmd, colors: colors}, nil
}

// Print prints the provided data to stdout.
func (p *Printer) Print(data interface{}) error {
	format := strings.ToLower(viper.GetString("format"))
	if format == "" || format == "yaml" {
		return yaml.NewEncoder(
			ansi.NewAnsiStdout(),
			yaml.EncoderColors(p.colors),
			yaml.EncoderDateKeys([]glob.Glob{
				glob.MustCompile("last_login"),
				glob.MustCompile("user_since"),
				glob.MustCompile("date"),
				glob.MustCompile("*_date"),
			})).Encode(data)
	} else if format == "json" {
		encoder := json.NewEncoder(ansi.NewAnsiStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(data)
	} else if format == "csv" {
		return csv.NewEncoder(ansi.NewAnsiStdout()).Encode(data)
	} else {
		return errors.New("unknown format")
	}
}

// PrintSyncMap prints a sync.Map.
func (p *Printer) PrintSyncMap(sm *sync.Map) error {
	m := make(map[string]interface{})
	sm.Range(func(key, value interface{}) bool {
		m[key.(string)] = value
		return true
	})
	if viper.IsSet("include") || viper.IsSet("exclude") {
		m = FilterMap(m,
			viper.GetStringSlice("include"),
			viper.GetStringSlice("exclude"))
	}
	return p.Print(m)
}

// ObjectToMap function that returns the attributes for an object as a map.
// Keys are attribute names and values are the attribute's value. Two special
// keys _id and _type are also included in the map with object's identifier
// and type respectively. The map is filtered according to the filters specified
// in the --include and --exclude command-line arguments.
func ObjectToMap(obj *vt.Object) map[string]interface{} {
	m := make(map[string]interface{})
	m["_id"] = obj.ID()
	m["_type"] = obj.Type()

	contextAttributes := make(map[string]interface{})
	for _, attr := range obj.ContextAttributes() {
		contextAttributes[attr], _ = obj.GetContext(attr)
	}
	if len(contextAttributes) > 0 {
		m["_context_attributes"] = contextAttributes
	}

	for _, attr := range obj.Attributes() {
		m[attr], _ = obj.Get(attr)
	}
	for _, name := range obj.Relationships() {
		r, _ := obj.GetRelationship(name)
		relatedObjs := r.Objects()
		if r.IsOneToOne() {
			if len(relatedObjs) > 0 {
				m[name] = relatedObjs[0].ID()
			} else {
				m[name] = nil
			}
		} else {
			l := make([]string, 0)
			for _, obj := range relatedObjs {
				l = append(l, obj.ID())
			}
			m[name] = l
		}
	}
	return m
}

// PrintObjects prints all the specified objects to stdout.
func (p *Printer) PrintObjects(objs []*vt.Object) error {
	list := make([]map[string]interface{}, 0)
	for _, obj := range objs {
		m := ObjectToMap(obj)
		if viper.IsSet("include") || viper.IsSet("exclude") {
			m = FilterMap(m,
				viper.GetStringSlice("include"),
				viper.GetStringSlice("exclude"))
		}
		if len(m) > 0 {
			list = append(list, m)
		}
	}
	if len(list) > 0 {
		return p.Print(list)
	}
	return nil
}

// PrintObject prints the specified object to stdout.
func (p *Printer) PrintObject(obj *vt.Object) error {
	objs := make([]*vt.Object, 1)
	objs[0] = obj
	return p.PrintObjects(objs)
}

// GetAndPrintObjects retrieves objects from the specified endpoint and prints
// them. The endpoint must contain a %s placeholder that will be replaced with
// items from the args slice. If args contains a single "-" string, the args are
// read from stdin one per line. If argRe is non-nil, only args that match the
// regular expression are used and the rest are discarded.
func (p *Printer) GetAndPrintObjects(endpoint string, r StringReader, argRe *regexp.Regexp) error {
	return p.GetAndPrintObjectsWithFallback([]string{endpoint}, r, argRe)
}

// GetAndPrintObjectsWithFallback retrieves objects from the specified endpoints and
// prints them. The function tries the endpoints in the order they are provided
// until one of them returns the object. The endpoint must contain a %s placeholder
// that will be replaced with items from the args slice. If args contains a single
// "-" string, the args are read from stdin one per line. If argRe is non-nil, only
// args that match the regular expression are used and the rest are discarded.
func (p *Printer) GetAndPrintObjectsWithFallback(endpoints []string, r StringReader, argRe *regexp.Regexp) error {
	if argRe != nil {
		r = NewFilteredStringReader(r, argRe)
	}

	filteredArgs := make([]string, 0)
	for s, err := r.ReadString(); s != "" || err == nil; s, err = r.ReadString() {
		filteredArgs = append(filteredArgs, s)
	}

	objectsCh := make(chan *vt.Object)
	errorsCh := make(chan error, len(filteredArgs))

	go p.client.RetrieveObjectsWithFallback(endpoints, filteredArgs, objectsCh, errorsCh)

	if viper.GetBool("identifiers-only") {
		var objectIds []string
		for obj := range objectsCh {
			objectIds = append(objectIds, obj.ID())
		}
		if err := p.Print(objectIds); err != nil {
			return err
		}
	} else {
		var objects []*vt.Object
		for obj := range objectsCh {
			objects = append(objects, obj)
		}
		if err := p.PrintObjects(objects); err != nil {
			return err
		}
	}

	for err := range errorsCh {
		fmt.Fprintln(os.Stderr, err)
	}

	return nil
}

// PrintCollection prints a collection of objects retrieved from the collection
// specified by the collection URL.
func (p *Printer) PrintCollection(collection *url.URL) error {
	it, err := p.client.Iterator(collection,
		vt.IteratorLimit(viper.GetInt("limit")),
		vt.IteratorCursor(viper.GetString("cursor")),
		vt.IteratorFilter(viper.GetString("filter")))
	if err != nil {
		return err
	}
	return p.PrintIterator(it)
}

// PrintIterator prints the objects returned by an object iterator.
func (p *Printer) PrintIterator(it *vt.Iterator) error {
	var objs []*vt.Object
	var ids []string
	for it.Next() {
		obj := it.Get()
		if viper.GetBool("identifiers-only") {
			ids = append(ids, obj.ID())
		} else {
			objs = append(objs, obj)
		}
	}
	if err := it.Error(); err != nil {
		return err
	}

	if viper.GetBool("identifiers-only") {
		if err := p.Print(ids); err != nil {
			return err
		}
	} else {
		if err := p.PrintObjects(objs); err != nil {
			return err
		}
	}
	p.PrintCommandLineWithCursor(it)
	return nil
}

// PrintCommandLineWithCursor prints the same command-line that was used for
// executing the program but adding or replacing the --cursor flag with
// the current cursor for the given iterator.
func (p *Printer) PrintCommandLineWithCursor(it *vt.Iterator) {
	if cursor := it.Cursor(); cursor != "" {
		args := p.cmd.Flags().Args()
		for i, arg := range args {
			args[i] = fmt.Sprintf("'%s'", arg)
		}
		flags := make([]string, 0)
		p.cmd.Flags().Visit(func(flag *pflag.Flag) {
			if flag.Name != "cursor" {
				var f string
				switch flag.Value.Type() {
				case "stringSlice":
					ss, _ := p.cmd.Flags().GetStringSlice(flag.Name)
					f = fmt.Sprintf("--%s='%s'", flag.Name, strings.Join(ss, ","))
				default:
					f = fmt.Sprintf("--%s=%v", flag.Name, flag.Value.String())
				}
				flags = append(flags, f)
			}
		})
		flags = append(flags, fmt.Sprintf("--cursor=%s", cursor))
		color.New(color.Faint).Fprintf(
			ansi.NewAnsiStderr(), "\nMORE WITH:\n%s %s %s\n",
			p.cmd.CommandPath(), strings.Join(args, " "), strings.Join(flags, " "))
	}
}
