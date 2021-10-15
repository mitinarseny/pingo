package ping

import (
	"context"
	"math"
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
	m  map[uint16]*pending
	mu sync.RWMutex

	r *reserve
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

// reserve stores unique uint16 sequence 
type reserve struct {
	toFree chan<- uint16
	freed  <-chan uint16
}

func newReserve() *reserve {
	toFree, freed := makeReserveCh()
	return &reserve{
		toFree: toFree,
		freed:  freed,
	}
}

// close frees resources allocated for reserve
func (r *reserve) close() {
	close(r.toFree)
}

// get allocates unique uint16 unless ctx is done. The returned number should
// then be freed with reserve.free() to make it availbale for future usage.
func (r *reserve) get(ctx context.Context) (uint16, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case id := <-r.freed:
		return id, nil
	}
}

// free pushes back given id, making it available to reserve.get() again.
func (r *reserve) free(id uint16) {
	r.toFree <- id
}

// TODO: doc
func makeReserveCh() (chan<- uint16, <-chan uint16) {
	ch := make(chan uint16, 1<<16)
	for seq := uint16(0); ; seq++ {
		ch <- seq
		if seq == 1<<16-1 {
			break
		}
	}
	return ch, ch
}

// TODO: remove?
// makeReserveCh creates FIFO with reserved values pushed to the read side
// of the channel when there is actually no data to read. Values are taken
// from range [min, max). Each of these values is pushed only once.
// Read side of the channel is closed when all of values sent to the write
// side of the channel had been received after the write side has been closed.
func makeReserveCh1() (chan<- uint16, <-chan uint16) {
	in, out := make(chan uint16), make(chan uint16)
	var used uint16
	go func() {
		inQ := make([]uint16, 0, 1)
		var (
			outCh  chan<- uint16
			curVal uint16
		)
		for in != nil || len(inQ) > 0 {
			if len(inQ) == 0 && used < math.MaxUint16 {
				inQ = append(inQ, used)
				used++
			}
			if len(inQ) > 0 {
				outCh = out
				curVal = inQ[0]
			} else {
				outCh = nil
			}
			select {
			case v, ok := <-in:
				if !ok {
					// send the rest to out and return
					for _, v := range inQ {
						out <- v
					}
					close(out)
					return
				}
				select {
				case out <- v:
				default:
					inQ = append(inQ, v)
				}
			case outCh <- curVal:
				l := len(inQ)
				inQ[0] = inQ[l-1]
				inQ = inQ[:l-1]
			}
		}
	}()
	return in, out
}
