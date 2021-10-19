package ping

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Pinger struct {
	c  net.PacketConn
	rc syscall.RawConn

	seqs   *sequences
	optIDs *optIDs

	// proto is unix.IPPROTO_ICMP(V6)
	proto int
}

// New creates a new Pinger with given local address to bind to.
// If laddr is nil or laddr.IP is nil, then it will be bound to 0.0.0.0.
// opts are setsockopt(2) options to set on the underlying socket.
//
// To enable receiving packets, Listen() should be called on returned Pinger.
// Close() should be called after Listen() returns.
func New(laddr *net.UDPAddr, opts ...WOption) (p *Pinger, err error) {
	if laddr == nil {
		laddr = new(net.UDPAddr)
	}
	if laddr.IP == nil {
		laddr.IP = net.IPv4zero
	}
	var family, proto int
	if laddr.IP.To4() != nil {
		family, proto = unix.AF_INET, unix.IPPROTO_ICMP
	} else {
		family, proto = unix.AF_INET6, unix.IPPROTO_ICMPV6
	}

	c, err := newConn(family, proto, laddr)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			c.Close()
		}
	}()

	rc, err := c.(syscall.Conn).SyscallConn()
	if err != nil {
		return nil, err
	}

	p = &Pinger{
		c:      c,
		rc:     rc,
		seqs:   newSequences(),
		optIDs: newOptIDs(),
		proto:  proto,
	}

	opts = append(opts, timestamping(unix.SOF_TIMESTAMPING_SOFTWARE|
		unix.SOF_TIMESTAMPING_RX_SOFTWARE|
		unix.SOF_TIMESTAMPING_TX_SCHED|
		unix.SOF_TIMESTAMPING_OPT_CMSG|
		unix.SOF_TIMESTAMPING_OPT_ID|
		unix.SOF_TIMESTAMPING_OPT_TSONLY))
	switch family {
	case unix.AF_INET:
		opts = append(opts, recvErr(true), recvTTL(true))
	case unix.AF_INET6:
		opts = append(opts, recvErr6(true), recvHopLimit(true))
	}
	if err := p.Set(opts...); err != nil {
		return nil, err
	}

	if err := p.rLock(); err != nil {
		return nil, err
	}

	return p, nil
}

// IsIPv6 returns whether IPv6 is used, otherwise IPv4
func (p *Pinger) IsIPv6() bool {
	return p.proto == unix.IPPROTO_ICMPV6
}

// Close releases resources allocated for Pinger.
// In particular, it closes the underlying socket.
func (p *Pinger) Close() error {
	return p.c.Close()
}

// Listen handles receiving of incomming replies and dispatches them into calling
// Pinger.Ping* method, so *no* Pinger.Ping*() methods should be called before
// Listen and after it returns.
//
// NOTE: It is a blocking call, so it should be run as a separate goroutine.
// It returns a non-nil error if context is done or an error occured
// while receiving on sokcet.
func (p *Pinger) Listen(ctx context.Context) error {
	if err := p.rUnlock(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	var g sync.WaitGroup
	g.Add(1)
	go func() {
		defer g.Done()

		<-ctx.Done()
		_ = p.rLock()
	}()
	defer func() {
		cancel()
		g.Wait()
	}()

	const numMsgs = 100
	ch := make(chan sockMsg, numMsgs)
	defer close(ch)

	go p.dispatcher(ch)

	err := p.read(ch, numMsgs)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		err = ctx.Err()
	}
	return err
}

type Reply struct {
	// RTT is a round trip time: the interval between sending
	// an ICMP Echo Request and receiving ICMP Echo Reply.
	RTT time.Duration

	// TTL is time-to-live field from the recieved IP packet
	TTL uint8

	// Data is a reply payload
	Data []byte

	// Err is not nil if ICMP error was received.
	// Other fields are valid even if Err is not nil.
	Err ICMPError
}

// PingContextPayload sends one ICMP Echo Request to given destination with
// given payload and waits for the reply until the given context is done.
// opts can be used to set per-packet sendmsg(2) options
//
// On success, it returns the reply.
// Otherwise, it returns an error occured while sending on underlying socket,
// ctx.Err() or ICMPError. If the returned error is ICMPError, then the
// returned Reply contains valid fields and has the same Err.
func (p *Pinger) PingContextPayload(ctx context.Context, dst net.IP, payload []byte,
	opts ...WOption) (Reply, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	seq, ch, err := p.seqs.add(ctx)
	if err != nil {
		return Reply{}, err
	}
	defer p.seqs.free(seq)

	if err := p.sendSeq(seq, dst, payload, opts...); err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			err = fmt.Errorf("Listen() is not running: %w", err)
		}
		return Reply{}, err
	}

	select {
	case <-ctx.Done():
		return Reply{}, ctx.Err()
	case r := <-ch:
		return r, r.Err
	}
}

// PingContext is like PingContextPayload, but with no payload.
func (p *Pinger) PingContext(ctx context.Context, dst net.IP, opts ...WOption) (Reply, error) {
	return p.PingContextPayload(ctx, dst, nil, opts...)
}

// PingPayload is like PingContextPayload, but with background context.
func (p *Pinger) PingPayload(dst net.IP, payload []byte, opts ...WOption) (Reply, error) {
	return p.PingContextPayload(context.Background(), dst, payload, opts...)
}

// Ping is like PingContext, but with background context.
func (p *Pinger) Ping(dst net.IP, opts ...WOption) (Reply, error) {
	return p.PingContext(context.Background(), dst, opts...)
}

// PingContextTimeoutPayload is like PingContextPayload, but it waits for the
// reply until timeout is passed or given context id done.
// Zero timeout means no timeout, so PingContextTimeout(ctx, dst, 0) is
// equialent to PingContext(ctx, dst)
func (p *Pinger) PingContextPayloadTimeout(ctx context.Context, dst net.IP,
	payload []byte, timeout time.Duration, opts ...WOption) (Reply, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return p.PingContextPayload(ctx, dst, payload, opts...)
}

// PingContextTimeout is like PingContextPayloadTimeout, but with no payload.
func (p *Pinger) PingContextTimeout(ctx context.Context, dst net.IP,
	timeout time.Duration, opts ...WOption) (Reply, error) {
	return p.PingContextPayloadTimeout(ctx, dst, nil, timeout, opts...)
}

// PingPayloadTimeout is like PingContextPayloadTimeout, but with background context.
func (p *Pinger) PingPayloadTimeout(dst net.IP, payload []byte,
	timeout time.Duration, opts ...WOption) (Reply, error) {
	return p.PingContextPayloadTimeout(context.Background(), dst, nil, timeout, opts...)
}

// PingTimeout is like PingPayloadTimeout, but no payload.
func (p *Pinger) PingTimeout(dst net.IP, timeout time.Duration, opts ...WOption) (Reply, error) {
	return p.PingPayloadTimeout(dst, nil, timeout, opts...)
}

type Replies []Reply

// AvgRTT returns average RTT across successful replies.
func (rs Replies) AvgRTT() time.Duration {
	var avg time.Duration
	for _, r := range rs {
		if r.Err != nil {
			continue
		}
		avg += r.RTT
	}
	return avg / time.Duration(len(rs))
}

// PingChContextPayloadIntervalTimeout sends ICMP Echo Requests with given
// payload periodically with given interval (zero interval means send next
// packet righ after the reply to the previuos one has been recieved) and
// waits for every reply until given context is done or non-zero timeout
// is passed.
// It returns a channel, where replies are sent to. The channel is closed
// when the context is done, so the caller should receive on that channel
// until it is closed.
func (p *Pinger) PingChContextPayloadIntervalTimeout(ctx context.Context, payload []byte,
	dst net.IP, interval, timeout time.Duration, opts ...WOption) <-chan Reply {
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
			r, err := p.PingContextPayloadTimeout(ctx, dst, payload, timeout, opts...)
			select {
			case <-ctx.Done():
				return
			case ch <- r:
			}
			if !(errors.Is(err, ctx.Err())) {
				return
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

// PingChContextIntervalTimeout is like PingChContextPayloadIntervalTimeout,
// but with no payload.
func (p *Pinger) PingChContextIntervalTimeout(ctx context.Context, dst net.IP,
	interval, timeout time.Duration, opts ...WOption) <-chan Reply {
	return p.PingChContextPayloadIntervalTimeout(ctx, dst, nil, interval, timeout, opts...)
}

// PingChContextPayloadInterval is the same as PingChContextIntervalTimeout,
// but with timeout equal to the interval, so it waits for reply to each request
// until interval has passed.
func (p *Pinger) PingChContextPayloadInterval(ctx context.Context, dst net.IP,
	payload []byte, interval time.Duration, opts ...WOption) <-chan Reply {
	return p.PingChContextPayloadIntervalTimeout(ctx, dst, payload, interval, interval, opts...)
}

// PingChContextInterval is like PingChContextPayloadInterval, but with no payload.
func (p *Pinger) PingChContextInterval(ctx context.Context, dst net.IP,
	interval time.Duration, opts ...WOption) <-chan Reply {
	return p.PingChContextIntervalTimeout(ctx, dst, interval, interval, opts...)
}

// PingChContextPayloadTimeout is the same as PingChContextPayloadIntervalTimeout,
// but echo requests are sent one by one, without waiting for interval to pass.
func (p *Pinger) PingChContextPayloadTimeout(ctx context.Context, dst net.IP,
	payload []byte, timeout time.Duration, opts ...WOption) <-chan Reply {
	return p.PingChContextPayloadIntervalTimeout(ctx, dst, payload, 0, timeout, opts...)
}

// PingChContextTimeout is like PingChContextPayloadTimeout, but with no payload.
func (p *Pinger) PingChContextTimeout(ctx context.Context, dst net.IP,
	timeout time.Duration, opts ...WOption) <-chan Reply {
	return p.PingChContextPayloadTimeout(ctx, dst, nil, timeout, opts...)
}

// PingChContextPayload is the same as PingChContextPayloadTimeout,
// but with no timeout, so it waits for each reply until context is done.
func (p *Pinger) PingChContextPayload(ctx context.Context, dst net.IP,
	payload []byte, opts ...WOption) <-chan Reply {
	return p.PingChContextPayloadTimeout(ctx, dst, payload, 0, opts...)
}

// PingChContext is like PingChContextPayload, but with no payload.
func (p *Pinger) PingChContext(ctx context.Context, dst net.IP, opts ...WOption) <-chan Reply {
	return p.PingChContextPayload(ctx, dst, nil, opts...)
}

// PingChPayloadTimeout is the same as PingChContextPayloadTimeout,
// but with background context, so it pings forever.
func (p *Pinger) PingChPayloadTimeout(dst net.IP, payload []byte,
	timeout time.Duration, opts ...WOption) <-chan Reply {
	return p.PingChContextPayloadTimeout(context.Background(), dst, payload, timeout, opts...)
}

// PingChTimeout is like PingChPayloadTimeout, but with no payload
func (p *Pinger) PingChTimeout(dst net.IP, timeout time.Duration, opts ...WOption) <-chan Reply {
	return p.PingChContextPayloadTimeout(context.Background(), dst, nil, timeout, opts...)
}

// PingChPayloadInterval is the same as PingChContextPayloadInterval,
// but with background timeout, so it pings forever.
func (p *Pinger) PingChPayloadInterval(dst net.IP, payload []byte,
	interval time.Duration, opts ...WOption) <-chan Reply {
	return p.PingChContextPayloadInterval(context.Background(), dst, payload, interval, opts...)
}

// PingChInterval is like PingChPayloadInterval, but with no payload.
func (p *Pinger) PingChInterval(dst net.IP, interval time.Duration, opts ...WOption) <-chan Reply {
	return p.PingChPayloadInterval(dst, nil, interval, opts...)
}

// PingChPayload is the same as PingChContextPayload, but with background
// context, so it pings forever.
func (p *Pinger) PingChPayload(dst net.IP, payload []byte, opts ...WOption) <-chan Reply {
	return p.PingChContextPayload(context.Background(), payload, dst, opts...)
}

// PingCh is like PingChPayload, but with no payload.
func (p *Pinger) PingCh(dst net.IP, opts ...WOption) <-chan Reply {
	return p.PingChPayload(dst, nil, opts...)
}

// PingNContextPayloadIntervalTimeout sends at most n ICMP Echo Requests with
// a given payload and interval (zero interval means send packets one by one
// and do not wait for interval to pass) and returns slice of received Replies
// until the first occurred connection error if there was any.
// Zero timeout means wait for each reply until the context is done.
func (p *Pinger) PingNContextPayloadIntervalTimeout(ctx context.Context, dst net.IP, n int,
	payload []byte, interval, timeout time.Duration, opts ...WOption) (Replies, error) {
	var ticker *time.Ticker
	if interval > 0 {
		checkIntervalTimeout(interval, timeout)
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	rs := make(Replies, 0, n)
	for ; n > 0; n-- {
		r, err := p.PingContextPayloadTimeout(ctx, dst, payload, timeout, opts...)
		if err != nil {
			return rs, err
		}
		rs = append(rs, r)
		if ticker == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return rs, ctx.Err()
		case <-ticker.C:
			continue
		}
	}
	return rs, nil
}

// PingNContextInterval is the same as PingNContextIntervalTimeout, but with
// timeout equal to the interval, so it waits for reply to each request until
// interval has passed.
func (p *Pinger) PingNContextPayloadInterval(ctx context.Context, dst net.IP, n int,
	payload []byte, interval time.Duration, opts ...WOption) (Replies, error) {
	return p.PingNContextPayloadIntervalTimeout(ctx, dst, n, payload, interval, interval, opts...)
}

// PingNContextInterval is like PingNContextPayloadInterval, but with no payload.
func (p *Pinger) PingNContextInterval(ctx context.Context, dst net.IP, n int,
	interval time.Duration, opts ...WOption) (Replies, error) {
	return p.PingNContextPayloadInterval(ctx, dst, n, nil, interval, opts...)
}

// PingNContextPayloadTimeout is the same as PingNContextPayloadIntervalTimeout,
// but echo requests are sent one by one, without waiting for interval to pass.
func (p *Pinger) PingNContextPayloadTimeout(ctx context.Context, dst net.IP, n int,
	payload []byte, timeout time.Duration, opts ...WOption) (Replies, error) {
	return p.PingNContextPayloadIntervalTimeout(ctx, dst, n, payload, 0, timeout, opts...)
}

// PingNContextTimeout is like PingNContextPayloadTimeout, but with no payload.
func (p *Pinger) PingNContextTimeout(ctx context.Context, dst net.IP, n int,
	timeout time.Duration, opts ...WOption) (Replies, error) {
	return p.PingNContextPayloadTimeout(ctx, dst, n, nil, timeout, opts...)
}

// PingNContextPayload is the same as PingNContextPayloadTimeout, but with no
// timeout, so it waits for each reply until context is done.
func (p *Pinger) PingNContextPayload(ctx context.Context, dst net.IP, n int,
	payload []byte, opts ...WOption) (Replies, error) {
	return p.PingNContextPayloadTimeout(ctx, dst, n, payload, 0, opts...)
}

// PingNContext is like PingNContextPayload, but with no payload.
func (p *Pinger) PingNContext(ctx context.Context, dst net.IP, n int,
	opts ...WOption) (Replies, error) {
	return p.PingNContextTimeout(ctx, dst, n, 0, opts...)
}

// PingNPayloadTimeout is the same as PingNContextPayloadTimeout, but with background
// context, so it tries to ping exactly n times.
func (p *Pinger) PingNPayloadTimeout(dst net.IP, n int, payload []byte,
	timeout time.Duration, opts ...WOption) (Replies, error) {
	return p.PingNContextPayloadTimeout(context.Background(), dst, n, payload, timeout, opts...)
}

// PingNTimeout is like PingNPayloadTimeout, but wuth no payload.
func (p *Pinger) PingNTimeout(dst net.IP, n int, timeout time.Duration,
	opts ...WOption) (Replies, error) {
	return p.PingNContextPayloadTimeout(context.Background(), dst, n, nil, timeout, opts...)
}

// PingNPayloadInterval is the same as PingNPayloadTimeoutInterval, but with background
// context, so it tries to ping exactly n times.
func (p *Pinger) PingNPayloadInterval(dst net.IP, n int, payload []byte,
	interval time.Duration, opts ...WOption) (Replies, error) {
	return p.PingNContextPayloadInterval(context.Background(), dst, n, payload, interval, opts...)
}

// PingNInterval is like PingNPayloadInterval, but with no payload.
func (p *Pinger) PingNInterval(dst net.IP, n int, interval time.Duration,
	opts ...WOption) (Replies, error) {
	return p.PingNPayloadInterval(dst, n, nil, interval, opts...)
}

// PingNPayload is the same as PingNContextPayload, but with background context,
// so it tries to ping exactly n times.
func (p *Pinger) PingNPayload(dst net.IP, n int, payload []byte,
	opts ...WOption) (Replies, error) {
	return p.PingNContextPayload(context.Background(), dst, n, payload, opts...)
}

// PingN is like PingNPayload, but with no payload
func (p *Pinger) PingN(dst net.IP, n int, opts ...WOption) (Replies, error) {
	return p.PingNPayload(dst, n, nil, opts...)
}

func checkIntervalTimeout(interval, timeout time.Duration) {
	if !(0 < timeout && timeout <= interval) {
		panic("timeout should be in range (0, interval]")
	}
}
