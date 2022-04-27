package ping

import (
	"sync"
	"sync/atomic"
)

// optIDs associates optIDs got from unix.SOF_TIMESTAMPING_OPT_ID
// with corresponding ICMP sequence numbers.
type optIDs struct {
	counter uint32
	m       map[uint32]uint16
	mu      sync.RWMutex
}

func newOptIDs() *optIDs {
	return &optIDs{
		m: make(map[uint32]uint16),
	}
}

// inc increases the counter by one.
// It must be called after every successfull sendmsg(2) syscall.
func (o *optIDs) inc() {
	optID := atomic.AddUint32(&o.counter, 1)
	o.pop(optID)
}

// now associates optID that has been just generated by kernel
// with given ICMP sequence number.
func (o *optIDs) now(seq uint16) {
	o.mu.RLock()
	o.m[o.counter] = seq
	o.mu.RUnlock()
}

// pop returns ICMP sequence number associated with given optID and
// frees associated resources.
func (o *optIDs) pop(optID uint32) (seq uint16, found bool) {
	o.mu.Lock()
	seq, found = o.m[optID]
	delete(o.m, optID)
	o.mu.Unlock()
	return seq, found
}
