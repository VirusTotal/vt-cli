package utils

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/plusvic/go-ansi"
)

// Coordinator coordinates the output of multiple threads to stdout.
type Coordinator struct {
	Threads int
}

// StringReader is the
type StringReader interface {
	ReadString() string
}

// StringArrayReader is a wrapper around a slice of strings that implements
// the StringReader interface.
type StringArrayReader struct {
	strings []string
	pos     int
}

// NewStringArrayReader creates a new StringArrayReader.
func NewStringArrayReader(strings []string) *StringArrayReader {
	return &StringArrayReader{strings: strings}
}

// ReadString reads one string from StringArrayReader. It returns an empty
// string if all the strings have been read already. This implies that StringArrayReader
// can not contain empty strings.
func (sar *StringArrayReader) ReadString() string {
	if sar.pos == len(sar.strings) {
		return ""
	}
	s := sar.strings[sar.pos]
	sar.pos++
	return s
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

// ReadString reads one string from StringIOReader. It returns an empty
// string if all the strings have been read already. This implies that StringIOReader
// can not contain empty strings.
func (sir *StringIOReader) ReadString() string {
	for sir.scanner.Scan() {
		s := strings.TrimSpace(sir.scanner.Text())
		if s != "" {
			return s
		}
	}
	return ""
}

type FilteredStringReader struct {
	reader StringReader
	re     *regexp.Regexp
}

func NewFilteredStringReader(r StringReader, re *regexp.Regexp) *FilteredStringReader {
	return &FilteredStringReader{reader: r, re: re}
}

func (fsr *FilteredStringReader) ReadString() string {
	s := fsr.reader.ReadString()
	for !fsr.re.MatchString(s) && s != "" {
		s = fsr.reader.ReadString()
	}
	return s
}

type DoerState struct {
	Progress string
}

type Doer interface {
	Do(string, *DoerState) string
}

// NewCoordinator ...
func NewCoordinator(threads int) *Coordinator {
	return &Coordinator{Threads: threads}
}

// DoWithArgReader ...
func (c *Coordinator) DoWithArgReader(doer Doer, argReader StringReader) {

	args := make([]string, 0)
	for arg := argReader.ReadString(); arg != ""; arg = argReader.ReadString() {
		args = append(args, arg)
	}

	argsCh := make(chan string)
	go func() {
		for _, arg := range args {
			argsCh <- arg
		}
		close(argsCh)
	}()

	c.DoWithArgCh(doer, argsCh)
}

// DoWithArgCh ...
func (c *Coordinator) DoWithArgCh(doer Doer, argsCh <-chan string) {

	resultsCh := make(chan string, c.Threads)
	doerStates := make([]DoerState, c.Threads)
	doersWg := &sync.WaitGroup{}

	for i := 0; i < c.Threads; i++ {
		doersWg.Add(1)
		go func(i int) {
			for arg := range argsCh {
				resultsCh <- doer.Do(arg, &doerStates[i])
				doerStates[i].Progress = ""
			}
			doersWg.Done()
		}(i)
	}

	printingWg := &sync.WaitGroup{}
	printingWg.Add(1)

	go printResults(resultsCh, doerStates, printingWg)

	doersWg.Wait()
	close(resultsCh)
	printingWg.Wait()
}

func printResults(resCh chan string, doerStates []DoerState, wg *sync.WaitGroup) {
Loop:
	for {
		select {
		case res, ok := <-resCh:
			if !ok {
				break Loop
			}
			ansi.Printf("%s", res)
			ansi.EraseInLine(0) // Clear to the end of the line.
			fmt.Println()
		default:
			// Print progress for pending workers
			lines := 0
			for _, ds := range doerStates {
				if ds.Progress != "" {
					ansi.Printf("%s", ds.Progress)
					ansi.EraseInLine(0) // Clear to the end of the line.
					fmt.Println()
					lines++
				}
			}
			time.Sleep(time.Millisecond * 250)
			if lines > 0 {
				// Move cursor up, to the line it was before printing worker's progress
				ansi.CursorPreviousLine(lines)
			}
		}
	}
	wg.Done()
}
