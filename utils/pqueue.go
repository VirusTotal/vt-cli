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

// PQueueNode is a node in a priority queues
type PQueueNode struct {
	Priority int
	Data     interface{}
}

// PQueue is a type implementing a priority queue
type PQueue []PQueueNode

func (pq PQueue) Len() int           { return len(pq) }
func (pq PQueue) Less(i, j int) bool { return pq[i].Priority < pq[j].Priority }
func (pq PQueue) Swap(i, j int)      { pq[i], pq[j] = pq[j], pq[i] }

// Push and Pop use pointer receivers because they modify the slice's length,
// not just its contents.

// Push add a value to the tail of the priority queue
func (pq *PQueue) Push(x interface{}) {
	*pq = append(*pq, x.(PQueueNode))
}

// Pop removes a value from the head of the priority queue
func (pq *PQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	x := old[n-1]
	*pq = old[0 : n-1]
	return x
}
