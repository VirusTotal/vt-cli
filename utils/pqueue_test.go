// Copyright © 2017 The VirusTotal CLI authors. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package utils_test

import (
	"container/heap"
	"testing"

	utils "github.com/VirusTotal/vt-cli/utils"
)

func TestPQueue(t *testing.T) {
	pq := utils.PQueue{}

	heap.Init(&pq)
	heap.Push(&pq, utils.PQueueNode{Priority: 4, Data: "4"})
	heap.Push(&pq, utils.PQueueNode{Priority: 0, Data: "0"})
	heap.Push(&pq, utils.PQueueNode{Priority: 2, Data: "2"})

	if heap.Pop(&pq).(utils.PQueueNode).Data.(string) != "0" {
		t.Errorf("")
	}

	heap.Push(&pq, utils.PQueueNode{Priority: 1, Data: "1"})

	if heap.Pop(&pq).(utils.PQueueNode).Data.(string) != "1" {
		t.Errorf("")
	}

	if heap.Pop(&pq).(utils.PQueueNode).Data.(string) != "2" {
		t.Errorf("")
	}

	if heap.Pop(&pq).(utils.PQueueNode).Data.(string) != "4" {
		t.Errorf("")
	}

	if pq.Len() != 0 {
		t.Errorf("")
	}

}
