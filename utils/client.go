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
func NewAPIClient(apiKey, agent string) (*APIClient, error) {
	c := vt.NewClient(apiKey)
	c.Agent = agent
	return &APIClient{c}, nil
}

// RetrieveObjects ...
func (c *APIClient) RetrieveObjects(objType string, objIDs []string, outCh chan *vt.Object, errCh chan error) error {

	// Make sure outCh is closed
	defer close(outCh)

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
	// their order in the input. As gorutines run in parallel the objects can
	// be sent out of order to objCh, but the order number is used to reorder
	// them.
	for order, objID := range objIDs {
		getWg.Add(1)
		go func(order int, objID string) {
			throttler <- nil
			obj, err := c.GetObject(vt.URL("%s/%s", objType, objID))
			if err == nil {
				objCh <- PQueueNode{Priority: order, Data: obj}
			} else {
				if apiErr, ok := err.(vt.Error); ok && apiErr.Code == "NotFoundError" {
					errCh <- err
				} else {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
			}
			getWg.Done()
			<-throttler
		}(order, objID)
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
				outCh <- h[0].Data.(*vt.Object)
				heap.Pop(&h)
				order++
			}
		}
		// Send to outCh any object remaining in the queue
		for h.Len() > 0 {
			outCh <- heap.Pop(&h).(PQueueNode).Data.(*vt.Object)
		}
		outWg.Done()
	}()

	// Wait for all objects to be retrieved
	getWg.Wait()

	// Once all object were retrieved is safe to close objCh and errCh
	close(objCh)
	close(errCh)

	// Wait for objects to be sent to outCh
	outWg.Wait()
	return nil
}
