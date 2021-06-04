package ping

import (
	"context"
	"math"
	"net"
	"time"
)

// pending holds information about the sent request
type pending struct {
	// ctx is context of the sender
	ctx context.Context

	// ch is where to send the reply to
	ch chan<- time.Duration

	// dst is the destination, which the request was sent to
	dst net.IP

	// sentAt is the time when the request was sent
	sentAt time.Time
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
// more needed
func (s *sequences) add(ctx context.Context, dst net.IP, sentAt time.Time) (uint16, <-chan time.Duration, error) {
	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case seq := <-s.available:
		ch := make(chan time.Duration, 1)
		s.pending[seq] = &pending{
			ctx:    ctx,
			ch:     ch,
			dst:    dst,
			sentAt: sentAt,
		}
		return seq, ch, nil
	}
}

// get returns pending request associated with given sequence number of nil
// if there is no such pending request
func (s *sequences) get(seq uint16) *pending {
	return s.pending[seq]
}

// free deletes the request from pending and deallocates given sequence number,
// so it becomes available again and can be taken with add()
func (s *sequences) free(seq uint16) {
	s.pending[seq] = nil
	s.available <- seq
}
