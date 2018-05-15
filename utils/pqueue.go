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
