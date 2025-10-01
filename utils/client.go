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
	"container/heap"
	"errors"
	"fmt"
	"os"
	"sync"

	vt "github.com/VirusTotal/vt-go"
	"github.com/spf13/viper"
)

// APIClient represents a VirusTotal API client.
type APIClient struct {
	*vt.Client
}

// NewAPIClient returns a new VirusTotal API client using the API key configured
// either using the program configuration file or the --apikey command-line flag.
func NewAPIClient(agent string) (*APIClient, error) {
	apikey := viper.GetString("apikey")
	if apikey == "" {
		return nil, errors.New(
			"An API key is needed. Either use the --apikey flag or run \"vt init\" to set up your API key")
	}
	c := vt.NewClient(apikey)
	c.Agent = agent
	return &APIClient{c}, nil
}

// RetrieveObjects retrieves objects from the specified endpoint. The endpoint
// must contain a %s placeholder that will be replaced with items from the args
// slice. The objects are put into the outCh as they are retrieved.
func (c *APIClient) RetrieveObjects(endpoint string, args []string, outCh chan *vt.Object, errCh chan error) error {
	return c.RetrieveObjectsWithFallback([]string{endpoint}, args, outCh, errCh)
}

// RetrieveObjectsWithFallback retrieves objects from the specified endpoints. It
// tries the endpoints in the order they are provided until one of them returns
// the object. The endpoint strings must contain a %s placeholder that will be
// replaced with items from the args slice. The objects are put into the outCh
// as they are retrieved.
func (c *APIClient) RetrieveObjectsWithFallback(endpoints []string, args []string, outCh chan *vt.Object, errCh chan error) error {

	// Make sure outCh and errCh are closed
	defer close(outCh)
	defer close(errCh)

	h := PQueue{}
	heap.Init(&h)

	objCh := make(chan PQueueNode)
	getWg := &sync.WaitGroup{}

	// Channel used for limiting the number of parallel goroutines
	threads := viper.GetInt("threads")

	if threads == 0 {
		panic("RetrieveObjects called with 0 threads")
	}

	throttler := make(chan interface{}, threads)

	// Read object IDs from the input channel, launch goroutines to retrieve the
	// objects and send them through objCh together with a number indicating
	// their order in the input. As goroutines run in parallel the objects can
	// be sent out of order to objCh, but the order number is used to reorder
	// them.
	for order, arg := range args {
		getWg.Add(1)
		go func(order int, arg string) {
			throttler <- nil
			var obj *vt.Object
			var err error
			for _, endpoint := range endpoints {
				obj, err = c.GetObject(vt.URL(endpoint, arg))
				if err == nil {
					objCh <- PQueueNode{Priority: order, Data: obj}
					break
				}
				if apiErr, ok := err.(vt.Error); ok && apiErr.Code == "NotFoundError" {
					// Try the next endpoint
				} else {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
			}
			if err != nil {
				objCh <- PQueueNode{Priority: order, Data: err}
			}
			getWg.Done()
			<-throttler
		}(order, arg)
	}

	outWg := &sync.WaitGroup{}
	outWg.Add(1)

	// Read objects from objCh, put them into a priority queue and send them in
	// their original order to outCh.
	go func() {
		order := 0
		for p := range objCh {
			heap.Push(&h, p)
			// If the object in the top of the queue is the next one in the order
			// it can be sent to outCh and removed from the queue, if not, we keep
			// pushing objects into the queue.
			if h[0].Priority == order {
				if obj, ok := h[0].Data.(*vt.Object); ok {
					outCh <- obj
				} else {
					errCh <- h[0].Data.(error)
				}
				heap.Pop(&h)
				order++
			}
		}
		// Send to outCh any object remaining in the queue
		for h.Len() > 0 {
			item := heap.Pop(&h).(PQueueNode).Data
			if obj, ok := item.(*vt.Object); ok {
				outCh <- obj
			} else {
				errCh <- item.(error)
			}
		}
		outWg.Done()
	}()

	// Wait for all objects to be retrieved
	getWg.Wait()

	// Once all object were retrieved is safe to close objCh.
	close(objCh)

	// Wait for objects to be sent to outCh
	outWg.Wait()

	return nil
}
