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
