package ping

import (
	"context"
	"math"
	"net"
	"sync/atomic"
	"time"
	"unsafe"
)

type reply struct {
	receivedAt time.Time
	payload    []byte
	err error
}

// pending holds information about the sent request
type pending struct {
	// ctx is context of the sender
	ctx context.Context

	// dst is the destination, which the request was sent to
	dst net.IP

	// reply is where to send the reply to
	reply chan<- reply
}

// sequences manages sequence numbers and associated with them pendings
type sequences struct {
	pending   []*pending
	available chan uint16
}

// newSequences creates new sequences with all 2^16 sequence numbers available
func newSequences() *sequences {
	available := make(chan uint16, 1<<16)
	for seq := uint16(0); ; seq++ {
		available <- seq
		if seq == math.MaxUint16 {
			// compare here to avoid uint16 overflow,
			// since uint16(1<<16-1) + 1 == uint16(0)
			// and loop will run indefinitely
			break
		}
	}
	return &sequences{
		pending:   make([]*pending, 1<<16),
		available: available,
	}
}

// add adds pending request and returns allocated sequence number and the
// channel, which the reply rtt is going to be sent to.
// The caller should call free(seq) when the allocated sequence number is no
// longer needed.
func (s *sequences) add(ctx context.Context, dst net.IP) (uint16, <-chan reply, error) {
	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case seq := <-s.available:
		rep := make(chan reply, 1)
		atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&s.pending[seq])),
			unsafe.Pointer(&pending{
				ctx:   ctx,
				reply: rep,
				dst:   dst,
			}))
		return seq, rep, nil
	}
}

// get returns active pending request associated with given sequence number
// It returns nil if there is no pending request for given sequence number.
func (s *sequences) get(seq uint16) *pending {
	return (*pending)(atomic.LoadPointer(
		(*unsafe.Pointer)(unsafe.Pointer(&s.pending[seq]))))
}

// free deallocates given sequence number, making it available again with add()
func (s *sequences) free(seq uint16) {
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&s.pending[seq])), nil)
	s.available <- seq
}
