package ping

import (
	"context"
	"sync"
	"time"
)

// pending holds information about the sent request
type pending struct {
	// ctx is context of the sender
	ctx context.Context

	// sentAt is the timestamp when the request was sent
	sentAt time.Time

	// reply is where to send the reply to
	reply chan<- Reply
}

// sequences associates ICMP sequence numbers with pending requests
type sequences struct {
	r reserve

	m  map[uint16]*pending
	mu sync.RWMutex
}

func newSequences() *sequences {
	return &sequences{
		m: make(map[uint16]*pending),
		r: newReserve(),
	}
}

// close frees resources allocated for sequences
func (s *sequences) close() {
	s.r.close()
}

// add returns available ICMP sequence number and a channel where send the Reply to
// unless given ctx is done.
func (s *sequences) add(ctx context.Context) (uint16, <-chan Reply, error) {
	seq, err := s.r.get(ctx)
	if err != nil {
		return 0, nil, err
	}
	rep := make(chan Reply, 1)
	s.mu.Lock()
	s.m[seq] = &pending{
		ctx:    ctx,
		sentAt: time.Now(),
		reply:  rep,
	}
	s.mu.Unlock()
	return seq, rep, nil
}

// sentAt updates the transmit timestamp for given ICMP sequence number.
// It should not be concurrently used with sequences.reply().
func (s *sequences) sentAt(seq uint16, sentAt time.Time) {
	pend := s.get(seq)
	if pend == nil {
		return
	}
	pend.sentAt = sentAt
}

// reply dispatches the reply for given sequence number to the sender.
// It should not be concurrentlyy used with sequences.sentAt()
func (s *sequences) reply(seq uint16, receivedAt time.Time,
	payload []byte, ttl uint8, icmpErr ICMPError) {
	pend := s.get(seq)
	if pend == nil {
		return
	}
	select {
	case <-pend.ctx.Done():
		// sender gave up waiting fr the reply
		return
	case pend.reply <- Reply{
		RTT:  receivedAt.Sub(pend.sentAt),
		TTL:  ttl,
		Data: payload,
		Err:  icmpErr,
	}:
	}
}

// get returns pending associates with given ICMP sequence number if any.
// Otherwise, it returns nil.
func (s *sequences) get(seq uint16) *pending {
	s.mu.RLock()
	p := s.m[seq]
	s.mu.RUnlock()
	return p
}

// free frees resources associated with given ICMP sequence number.
func (s *sequences) free(seq uint16) *pending {
	s.mu.Lock()
	p, found := s.m[seq]
	delete(s.m, seq)
	s.mu.Unlock()
	if !found {
		return nil
	}
	s.r.free(seq)
	return p
}

// reserve stores unique uint16 numbers
type reserve chan uint16

func newReserve() reserve {
	ch := make(chan uint16, 1<<16)
	for seq := uint16(0); ; seq++ {
		ch <- seq
		if seq == 1<<16-1 {
			break
		}
	}
	return ch
}

// close frees resources allocated for reserve
func (r reserve) close() {
	close(r)
}

// get allocates unique uint16 unless ctx is done. The returned number should
// then be freed with reserve.free() to make it availbale for future usage.
// Once get() returned a number, no other calls get() will return this number
// until free() is called with the number.
func (r reserve) get(ctx context.Context) (uint16, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case id := <-r:
		return id, nil
	}
}

// free pushes back given id, making it available to reserve.get() again.
func (r reserve) free(id uint16) {
	r <- id
}
