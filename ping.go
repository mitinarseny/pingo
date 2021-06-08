package ping

import (
	"context"
	"net"
	"os"
	"syscall"
	"time"
)

type Pinger struct {
	c    *net.UDPConn
	seqs *sequences

	// proto is IANA ICMP Protocol Number
	proto int
}

// New creates a new Pinger with given local and destination addresses.
// laddr should be a valid IP address, while dst could be nil.
// Non-nil dst means that ICMP packets could be sent to and received from
// only given address, pinging different address would result in error.
//
// To enable receiving packets, Listen() should be called on returned Pinger.
// Close() should be called after Listen() returns if Pinger is no more needed.
func New(laddr *net.UDPAddr, dst net.IP) (*Pinger, error) {
	c, proto, err := newConn(laddr, dst)
	if err != nil {
		return nil, err
	}

	return &Pinger{
		c:     c,
		seqs:  newSequences(),
		proto: proto,
	}, nil
}

// SetTTL with non-zero sets the given Time-to-Live on all outgoing IP packets.
// Pass zero ttl To get current value.
func (p *Pinger) SetTTL(ttl uint8) (uint8, error) {
	c, err := p.c.SyscallConn()
	if err != nil {
		return 0, err
	}
	c.Control(func(fd uintptr) {
		if ttl == 0 {
			var t int
			t, err = syscall.GetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TTL)
			ttl = uint8(t)
			err = os.NewSyscallError("getsockopt", err)
		} else {
			err = os.NewSyscallError("setsockopt",
				syscall.SetsockoptByte(int(fd), syscall.SOL_IP, syscall.IP_TTL, ttl))
		}
	})
	return ttl, err
}

// Close releases resources allocated for Pinger.
// In particular, it closes the underlying socket.
func (p *Pinger) Close() error {
	return p.c.Close()
}

// Listen should be called to start receiving of incomming replies
// and route them into calling Ping* method, so no Ping*() methods should be
// called before Listen and after it returns.
// It is a blocking call, so it should be run as a separate goroutine.
// It returns a non-nil error if context is done or an error occured
// while receiving on sokcet.
func (p *Pinger) Listen(ctx context.Context, readTimeout time.Duration) error {
	buff := make([]byte, 1500)
	for {
		seq, from, err := p.recvSeq(ctx, buff, readTimeout)
		if err != nil {
			return err
		}
		receivedAt := time.Now()
		pend := p.seqs.get(seq)
		if pend == nil || !from.IP.Equal(pend.dst) {
			// Drop the reply in following cases:
			//   * we did not send the echo request, which the reply came to
			//   * sender gave up waiting for the reply
			//   * the echo reply came from the address, which is different from
			//     the destination address, which the request was sent to
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-pend.ctx.Done():
			// sender gave up waiting for the reply
		case pend.receivedAt <- receivedAt:
			close(pend.receivedAt)
		}
	}
}

// PingContext sends one ICMP Echo Request to given destination and waits
// for the ICMP Echo Reply until the given context is done. On success,
// it returns the round trip time. Otherwise, it returns an error occured while
// sending on underlying socket or ctx.Err()
func (p *Pinger) PingContext(ctx context.Context, dst net.IP) (rtt time.Duration, err error) {
	seq, ch, err := p.seqs.add(ctx, dst)
	if err != nil {
		return 0, err
	}
	defer p.seqs.free(seq)

	if err := p.send(dst, seq); err != nil {
		return 0, err
	}
	sentAt := time.Now()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case receivedAt := <-ch:
		return receivedAt.Sub(sentAt), nil
	}
}

// Ping is like PingContext, but with background context.
func (p *Pinger) Ping(dst net.IP) (rtt time.Duration, err error) {
	return p.PingContext(context.Background(), dst)
}

// PingContextTimeout is like PingContext, but it waits for the reply until
// timeout is passed or given context id done.
// Zero timeout means no timeout, so PingContextTimeout(ctx, dst, 0) is
// equialent to PingContext(ctx, dst)
func (p *Pinger) PingContextTimeout(ctx context.Context, dst net.IP, timeout time.Duration) (rtt time.Duration, err error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return p.PingContext(ctx, dst)
}

// PingTimeout is like PingContextTimeout, but with background context.
func (p *Pinger) PingTimeout(dst net.IP, timeout time.Duration) (rtt time.Duration, err error) {
	return p.PingContextTimeout(context.Background(), dst, timeout)
}

type Reply struct {
	// RTT is a round trip time: the interval between sending
	// an ICMP Echo Request and receiving ICMP Echo Reply.
	RTT time.Duration

	// Err is an error occurred while sending ICMP Echo Request
	// or waiting for the reply
	Err error
}

// PingChContextIntervalTimeout sends ICMP Echo Requests periodically with
// given interval (zero interval means send next packet righ after the reply
// to the previuos one has been recieved) and waits for every reply until
// given context is done or non-zero timeout is passed.
// It returns a channel, where replies are sent to. The channel is closed
// when the context is done, so the caller should receive on that channel
// until it is closed.
func (p *Pinger) PingChContextIntervalTimeout(ctx context.Context, dst net.IP, interval, timeout time.Duration) <-chan Reply {
	ch := make(chan Reply)
	go func() {
		defer close(ch)

		var ticker *time.Ticker
		if interval > 0 {
			checkIntervalTimeout(interval, timeout)
			ticker = time.NewTicker(interval)
			defer ticker.Stop()
		}

		for {
			rtt, err := p.PingContextTimeout(ctx, dst, timeout)
			select {
			case <-ctx.Done():
				return
			case ch <- Reply{
				RTT: rtt,
				Err: err,
			}:
			}
			if ticker == nil {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return ch
}

// PingChContextInterval is the same as PingChContextIntervalTimeout, but with
// timeout equal to the interval, so it waits for reply to each request until
// interval has passed.
func (p *Pinger) PingChContextInterval(ctx context.Context, dst net.IP, interval time.Duration) <-chan Reply {
	return p.PingChContextIntervalTimeout(ctx, dst, interval, interval)
}

// PingChContextTimeout is the same as PingChContextIntervalTimeout, but echo
// requests are sent one by one, without waiting for interval to pass.
func (p *Pinger) PingChContextTimeout(ctx context.Context, dst net.IP, timeout time.Duration) <-chan Reply {
	return p.PingChContextIntervalTimeout(ctx, dst, 0, timeout)
}

// PingChContext is the same as PingChContextTimeout, but with no timeout,
// so it waits for each reply until context is done.
func (p *Pinger) PingChContext(ctx context.Context, dst net.IP) <-chan Reply {
	return p.PingChContextTimeout(ctx, dst, 0)
}

// PingChTimeout is the same as PingChContextTimeout, but with background
// context, so it pings forever.
func (p *Pinger) PingChTimeout(dst net.IP, timeout time.Duration) <-chan Reply {
	return p.PingChContextTimeout(context.Background(), dst, timeout)
}

// PingChInterval is the same as PingChContextInterval, but with background
// timeout, so it pings forever.
func (p *Pinger) PingChInterval(dst net.IP, interval time.Duration) <-chan Reply {
	return p.PingChContextInterval(context.Background(), dst, interval)
}

// PingCh is the same as PingChContext, but with background context,
// so it pings forever.
func (p *Pinger) PingCh(dst net.IP) <-chan Reply {
	return p.PingChContext(context.Background(), dst)
}

// PingNContextIntervalTimeout sends at most n ICMP Echo Requests with a given
// interval (zero interval means send packets one by one and do not wait for
// interval to pass) and returns average round trip time for successfully
// received replies within the given per-reply timeout. Zero timeout means wait
// for each reply ntil context is done.
// The returned number of successfully received replies can differ from n if
// any errors encountered while sending requests and receiving replies.
// The last non-nil error is returned.
func (p *Pinger) PingNContextIntervalTimeout(ctx context.Context, dst net.IP, n int, interval, timeout time.Duration) (avgRTT time.Duration, success int, err error) {
	var ticker *time.Ticker
	if interval > 0 {
		checkIntervalTimeout(interval, timeout)
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	for ; n > 0; n-- {
		rtt, perr := p.PingContextTimeout(ctx, dst, timeout)
		if perr == nil {
			avgRTT += rtt
			success++
		} else {
			err = perr
		}
		if ticker == nil {
			continue
		}
		select {
		case <-ctx.Done():
			if err == nil {
				err = ctx.Err()
			}
			goto breakLoop
		case <-ticker.C:
			continue
		}
	}
breakLoop:
	if success > 0 {
		avgRTT /= time.Duration(success)
	}
	return
}

// PingNContextInterval is the same as PingNContextIntervalTimeout, but with
// timeout equal to the interval, so it waits for reply to each request until
// interval has passed.
func (p *Pinger) PingNContextInterval(ctx context.Context, dst net.IP, n int, interval time.Duration) (avgRTT time.Duration, success int, err error) {
	return p.PingNContextIntervalTimeout(ctx, dst, n, interval, interval)
}

// PingNContextTimeout is the same as PingNContextIntervalTimeout, but echo
// requests are sent one by one, without waiting for interval to pass.
func (p *Pinger) PingNContextTimeout(ctx context.Context, dst net.IP, n int, timeout time.Duration) (avgRTT time.Duration, success int, err error) {
	return p.PingNContextIntervalTimeout(ctx, dst, n, 0, timeout)
}

// PingNContext is the same as PingNContextTimeout, but with no timeout,
// so it waits for each reply until context is done.
func (p *Pinger) PingNContext(ctx context.Context, dst net.IP, n int) (avgRTT time.Duration, success int, err error) {
	return p.PingNContextTimeout(ctx, dst, n, 0)
}

// PingNTimeout is the same as PingNTimeoutContext, but with background
// context, so it tries to ping exactly n times.
func (p *Pinger) PingNTimeout(dst net.IP, n int, timeout time.Duration) (avgRTT time.Duration, success int, err error) {
	return p.PingNContextTimeout(context.Background(), dst, n, timeout)
}

// PingNInterval is the same as PingNTimeoutInterval, but with background
// context, so it tries to ping exactly n times.
func (p *Pinger) PingNInterval(dst net.IP, n int, interval time.Duration) (avgRTT time.Duration, success int, err error) {
	return p.PingNContextInterval(context.Background(), dst, n, interval)
}

// PingN is the same as PingNContext, but with background context, so it tries
// to ping exactly n times.
func (p *Pinger) PingN(dst net.IP, n int) (avgRTT time.Duration, success int, err error) {
	return p.PingNContext(context.Background(), dst, n)
}

func checkIntervalTimeout(interval, timeout time.Duration) {
	if timeout == 0 || timeout > interval {
		panic("timeout should not be zero or greater than interval")
	}
}
