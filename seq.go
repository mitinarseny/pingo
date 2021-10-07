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

func (s *sequences) get(seq uint16) *pending {
	s.mu.RLock()
	p := s.m[seq]
	s.mu.RUnlock()
	return p
}

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

func (r *reserve) close() {
	close(r.toFree)
}

func (r *reserve) get(ctx context.Context) (uint16, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case id := <-r.freed:
		return id, nil
	}
}

func (r *reserve) free(id uint16) {
	r.toFree <- id
}
