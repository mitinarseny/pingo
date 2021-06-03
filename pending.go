package ping

import (
	"context"
	"math"
	"net"
	"time"
)

type pending struct {
	ctx    context.Context
	ch     chan<- time.Duration
	dst    net.IP
	sentAt time.Time
}

type sequences struct {
	pending   []*pending
	available chan uint16
}

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

func (s *sequences) get(seq uint16) *pending {
	return s.pending[seq]
}

func (s *sequences) free(seq uint16) {
	s.pending[seq] = nil
	s.available <- seq
}
