package ping

import "sync"

type optIDs struct {
	counter uint32
	m map[uint32]uint16
	mu sync.RWMutex
}

func newOptIDs() *optIDs {
	return &optIDs{
		m: make(map[uint32]uint16),
	}
}

func (o *optIDs) now(seq uint16) {
	o.mu.Lock()
	o.m[o.counter] = seq
	o.counter++
	o.mu.Unlock()
}

func (o *optIDs) pop(optID uint32) (seq uint16) {
	o.mu.RLock()
	seq = o.m[optID]
	delete(o.m, optID)
	o.mu.RUnlock()
	return seq
}
