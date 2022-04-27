package ping

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"sync"
	"time"

	unixx "github.com/mitinarseny/pingo/unix"
	"golang.org/x/net/bpf"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

type Pinger struct {
	c *unixx.SocketConn

	seqs *sequences

	currentOptID uint32
	optIDsToSeqs map[uint32]uint16
	mu           sync.Mutex

	// proto is unix.IPPROTO_ICMP(V6)
	proto int
}

// New creates a new Pinger with given local address to bind to.
// If laddr is nil or laddr.IP is nil, then it will be bound to 0.0.0.0.
// opts are setsockopt(2) options to set on the underlying socket.
//
// To enable receiving packets, Listen() should be called on returned Pinger.
// Close() should be called after Listen() returns.
func New(laddr *net.UDPAddr, opts ...unixx.WSockOpt) (p *Pinger, err error) {
	if laddr == nil {
		laddr = new(net.UDPAddr)
	}
	if laddr.IP == nil {
		laddr.IP = net.IPv4zero
	}
	var (
		family, proto int
		sa            unix.Sockaddr
	)
	switch {
	case laddr.IP.To4() != nil:
		family, proto = unix.AF_INET, unix.IPPROTO_ICMP
		sa4 := unix.SockaddrInet4{
			Port: laddr.Port,
		}
		copy(sa4.Addr[:], laddr.IP.To4())
		sa = &sa4
	case laddr.IP.To16() != nil:
		family, proto = unix.AF_INET6, unix.IPPROTO_ICMPV6
		sa6 := unix.SockaddrInet6{
			Port: laddr.Port,
		}
		copy(sa6.Addr[:], laddr.IP.To4())
		sa = &sa6
	default:
		return nil, errors.New("invalid IP address")
	}

	c, err := unixx.NewSocketConn(family, unix.SOCK_DGRAM, proto)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	if err := c.Bind(sa); err != nil {
		return nil, err
	}

	if err := c.AttachFilter([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 1},                       // TYPE
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0, SkipTrue: 3}, // TYPE == ICMP Echo Reply
		bpf.LoadAbsolute{Off: 1, Size: 1},                       // CODE
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0, SkipTrue: 1}, // CODE == 0
		bpf.RetConstant{Val: 1 << 16},                           // ACCEPT 2^16 bytes
		bpf.RetConstant{Val: 0},                                 // DROP
	}); err != nil {
		return nil, fmt.Errorf("attach filter: %w", err)
	}

	p = &Pinger{
		c:            c,
		seqs:         newSequences(),
		optIDsToSeqs: make(map[uint32]uint16),
		proto:        proto,
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

	if err := p.c.RLock(); err != nil {
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := p.c.SetReadContext(ctx); err != nil {
		return err
	}

	const numMsgs = 100
	ch := make(chan sockMsg, numMsgs)
	defer close(ch)

	err := p.read(ch, numMsgs)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		err = ctx.Err()
	}
	return err
}

type Reply struct {
	// From is the sender IP address of recevied reply.
	From net.IP

	// RTT is a round trip time: the time interval between sending
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

// Set sets given options on the underlying socket with setsockopt(2)
func (p *Pinger) Set(opts ...unixx.WSockOpt) error {
	return p.c.SetSockOpts(opts...)
}

// Get gets given options from the underlying socket with getsockopt(2)
func (p *Pinger) Get(opts ...unixx.RSockOpt) error {
	return p.c.GetSockOpts(opts...)
}

// Send just sends ICMP packet with given type, code and body to dst,
// ignoring sequence number management and timestamping, so it would
// not interfere with Ping* methods.
// opts can be used to set per-packet sendmsg(2) options.
func (p *Pinger) Send(typ icmp.Type, code uint8, body icmp.MessageBody,
	dst net.IP, opts ...unixx.WSockOpt) error {
	return p.send(typ, code, body, dst, nil, append(opts, timestamping(0))...)
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
	opts ...unixx.WSockOpt) (Reply, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	seq, ch, err := p.seqs.add(ctx)
	if err != nil {
		return Reply{}, err
	}
	defer p.seqs.free(seq)

	var typ icmp.Type
	switch p.proto {
	case unix.IPPROTO_ICMP:
		typ = ipv4.ICMPTypeEcho
	case unix.IPPROTO_ICMPV6:
		typ = ipv6.ICMPTypeEchoRequest
	}
	if err := p.send(typ, 0, &icmp.Echo{
		// ID is filled by kernel thanks to IPPROTO_ICMP(V6)
		Seq:  int(seq),
		Data: payload,
	}, dst, func() {
		// map current ICMP sequence number to optID
		// just generated by kernel thatks to unix.SOF_TIMESTAMPING_OPT_ID
		p.mu.Lock()
		p.optIDsToSeqs[p.currentOptID] = seq
		p.mu.Unlock()
	}, opts...); err != nil {
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
func (p *Pinger) PingContext(ctx context.Context, dst net.IP, opts ...unixx.WSockOpt) (Reply, error) {
	return p.PingContextPayload(ctx, dst, nil, opts...)
}

// PingPayload is like PingContextPayload, but with background context.
func (p *Pinger) PingPayload(dst net.IP, payload []byte, opts ...unixx.WSockOpt) (Reply, error) {
	return p.PingContextPayload(context.Background(), dst, payload, opts...)
}

// Ping is like PingContext, but with background context.
func (p *Pinger) Ping(dst net.IP, opts ...unixx.WSockOpt) (Reply, error) {
	return p.PingContext(context.Background(), dst, opts...)
}

// PingContextTimeoutPayload is like PingContextPayload, but it waits for the
// reply until timeout is passed or given context id done.
// Zero timeout means no timeout, so PingContextTimeout(ctx, dst, 0) is
// equialent to PingContext(ctx, dst)
func (p *Pinger) PingContextPayloadTimeout(ctx context.Context, dst net.IP,
	payload []byte, timeout time.Duration, opts ...unixx.WSockOpt) (Reply, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return p.PingContextPayload(ctx, dst, payload, opts...)
}

// PingContextTimeout is like PingContextPayloadTimeout, but with no payload.
func (p *Pinger) PingContextTimeout(ctx context.Context, dst net.IP,
	timeout time.Duration, opts ...unixx.WSockOpt) (Reply, error) {
	return p.PingContextPayloadTimeout(ctx, dst, nil, timeout, opts...)
}

// PingPayloadTimeout is like PingContextPayloadTimeout, but with background context.
func (p *Pinger) PingPayloadTimeout(dst net.IP, payload []byte,
	timeout time.Duration, opts ...unixx.WSockOpt) (Reply, error) {
	return p.PingContextPayloadTimeout(context.Background(), dst, nil, timeout, opts...)
}

// PingTimeout is like PingPayloadTimeout, but no payload.
func (p *Pinger) PingTimeout(dst net.IP, timeout time.Duration, opts ...unixx.WSockOpt) (Reply, error) {
	return p.PingPayloadTimeout(dst, nil, timeout, opts...)
}

type Replies []Reply

// iterRTT iterates over RTTs of all successfull replies and calls f on each of them.
func (rs Replies) iterRTT(f func(time.Duration)) {
	for _, r := range rs {
		if r.Err != nil {
			continue
		}
		f(r.RTT)
	}
}

// AvgRTT returns average RTT across successfull replies.
func (rs Replies) AvgRTT() time.Duration {
	var avg time.Duration
	rs.iterRTT(func(rtt time.Duration) {
		avg += rtt
	})
	return avg / time.Duration(len(rs))
}

// MaxRTT returns maximum RTT across successfull replies.
func (rs Replies) MaxRTT() time.Duration {
	var max time.Duration
	rs.iterRTT(func(rtt time.Duration) {
		if rtt > max {
			max = rtt
		}
	})
	return max
}

// MinRTT returns minimum RTT across successfull replies.
func (rs Replies) MinRTT() time.Duration {
	min := time.Duration(math.MaxInt64)
	rs.iterRTT(func(rtt time.Duration) {
		if rtt < min {
			min = rtt
		}
	})
	return min
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
	dst net.IP, interval, timeout time.Duration, opts ...unixx.WSockOpt) <-chan Reply {
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
			if err != r.Err && !errors.Is(err, ctx.Err()) {
				return
			}
			select {
			case <-ctx.Done():
				return
			case ch <- r:
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
	interval, timeout time.Duration, opts ...unixx.WSockOpt) <-chan Reply {
	return p.PingChContextPayloadIntervalTimeout(ctx, dst, nil, interval, timeout, opts...)
}

// PingChContextPayloadInterval is the same as PingChContextIntervalTimeout,
// but with timeout equal to the interval, so it waits for reply to each request
// until interval has passed.
func (p *Pinger) PingChContextPayloadInterval(ctx context.Context, dst net.IP,
	payload []byte, interval time.Duration, opts ...unixx.WSockOpt) <-chan Reply {
	return p.PingChContextPayloadIntervalTimeout(ctx, dst, payload, interval, interval, opts...)
}

// PingChContextInterval is like PingChContextPayloadInterval, but with no payload.
func (p *Pinger) PingChContextInterval(ctx context.Context, dst net.IP,
	interval time.Duration, opts ...unixx.WSockOpt) <-chan Reply {
	return p.PingChContextIntervalTimeout(ctx, dst, interval, interval, opts...)
}

// PingChContextPayloadTimeout is the same as PingChContextPayloadIntervalTimeout,
// but echo requests are sent one by one, without waiting for interval to pass.
func (p *Pinger) PingChContextPayloadTimeout(ctx context.Context, dst net.IP,
	payload []byte, timeout time.Duration, opts ...unixx.WSockOpt) <-chan Reply {
	return p.PingChContextPayloadIntervalTimeout(ctx, dst, payload, 0, timeout, opts...)
}

// PingChContextTimeout is like PingChContextPayloadTimeout, but with no payload.
func (p *Pinger) PingChContextTimeout(ctx context.Context, dst net.IP,
	timeout time.Duration, opts ...unixx.WSockOpt) <-chan Reply {
	return p.PingChContextPayloadTimeout(ctx, dst, nil, timeout, opts...)
}

// PingChContextPayload is the same as PingChContextPayloadTimeout,
// but with no timeout, so it waits for each reply until context is done.
func (p *Pinger) PingChContextPayload(ctx context.Context, dst net.IP,
	payload []byte, opts ...unixx.WSockOpt) <-chan Reply {
	return p.PingChContextPayloadTimeout(ctx, dst, payload, 0, opts...)
}

// PingChContext is like PingChContextPayload, but with no payload.
func (p *Pinger) PingChContext(ctx context.Context, dst net.IP, opts ...unixx.WSockOpt) <-chan Reply {
	return p.PingChContextPayload(ctx, dst, nil, opts...)
}

// PingChPayloadTimeout is the same as PingChContextPayloadTimeout,
// but with background context, so it pings forever.
func (p *Pinger) PingChPayloadTimeout(dst net.IP, payload []byte,
	timeout time.Duration, opts ...unixx.WSockOpt) <-chan Reply {
	return p.PingChContextPayloadTimeout(context.Background(), dst, payload, timeout, opts...)
}

// PingChTimeout is like PingChPayloadTimeout, but with no payload
func (p *Pinger) PingChTimeout(dst net.IP, timeout time.Duration, opts ...unixx.WSockOpt) <-chan Reply {
	return p.PingChContextPayloadTimeout(context.Background(), dst, nil, timeout, opts...)
}

// PingChPayloadInterval is the same as PingChContextPayloadInterval,
// but with background timeout, so it pings forever.
func (p *Pinger) PingChPayloadInterval(dst net.IP, payload []byte,
	interval time.Duration, opts ...unixx.WSockOpt) <-chan Reply {
	return p.PingChContextPayloadInterval(context.Background(), dst, payload, interval, opts...)
}

// PingChInterval is like PingChPayloadInterval, but with no payload.
func (p *Pinger) PingChInterval(dst net.IP, interval time.Duration, opts ...unixx.WSockOpt) <-chan Reply {
	return p.PingChPayloadInterval(dst, nil, interval, opts...)
}

// PingChPayload is the same as PingChContextPayload, but with background
// context, so it pings forever.
func (p *Pinger) PingChPayload(dst net.IP, payload []byte, opts ...unixx.WSockOpt) <-chan Reply {
	return p.PingChContextPayload(context.Background(), payload, dst, opts...)
}

// PingCh is like PingChPayload, but with no payload.
func (p *Pinger) PingCh(dst net.IP, opts ...unixx.WSockOpt) <-chan Reply {
	return p.PingChPayload(dst, nil, opts...)
}

// PingNContextPayloadIntervalTimeout sends at most n ICMP Echo Requests with
// a given payload and interval (zero interval means send packets one by one
// and do not wait for interval to pass) and returns slice of received Replies
// until the first occurred connection error if there was any.
// Zero timeout means wait for each reply until the context is done.
func (p *Pinger) PingNContextPayloadIntervalTimeout(ctx context.Context, dst net.IP, n int,
	payload []byte, interval, timeout time.Duration, opts ...unixx.WSockOpt) (Replies, error) {
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
	payload []byte, interval time.Duration, opts ...unixx.WSockOpt) (Replies, error) {
	return p.PingNContextPayloadIntervalTimeout(ctx, dst, n, payload, interval, interval, opts...)
}

// PingNContextInterval is like PingNContextPayloadInterval, but with no payload.
func (p *Pinger) PingNContextInterval(ctx context.Context, dst net.IP, n int,
	interval time.Duration, opts ...unixx.WSockOpt) (Replies, error) {
	return p.PingNContextPayloadInterval(ctx, dst, n, nil, interval, opts...)
}

// PingNContextPayloadTimeout is the same as PingNContextPayloadIntervalTimeout,
// but echo requests are sent one by one, without waiting for interval to pass.
func (p *Pinger) PingNContextPayloadTimeout(ctx context.Context, dst net.IP, n int,
	payload []byte, timeout time.Duration, opts ...unixx.WSockOpt) (Replies, error) {
	return p.PingNContextPayloadIntervalTimeout(ctx, dst, n, payload, 0, timeout, opts...)
}

// PingNContextTimeout is like PingNContextPayloadTimeout, but with no payload.
func (p *Pinger) PingNContextTimeout(ctx context.Context, dst net.IP, n int,
	timeout time.Duration, opts ...unixx.WSockOpt) (Replies, error) {
	return p.PingNContextPayloadTimeout(ctx, dst, n, nil, timeout, opts...)
}

// PingNContextPayload is the same as PingNContextPayloadTimeout, but with no
// timeout, so it waits for each reply until context is done.
func (p *Pinger) PingNContextPayload(ctx context.Context, dst net.IP, n int,
	payload []byte, opts ...unixx.WSockOpt) (Replies, error) {
	return p.PingNContextPayloadTimeout(ctx, dst, n, payload, 0, opts...)
}

// PingNContext is like PingNContextPayload, but with no payload.
func (p *Pinger) PingNContext(ctx context.Context, dst net.IP, n int,
	opts ...unixx.WSockOpt) (Replies, error) {
	return p.PingNContextTimeout(ctx, dst, n, 0, opts...)
}

// PingNPayloadTimeout is the same as PingNContextPayloadTimeout, but with background
// context, so it tries to ping exactly n times.
func (p *Pinger) PingNPayloadTimeout(dst net.IP, n int, payload []byte,
	timeout time.Duration, opts ...unixx.WSockOpt) (Replies, error) {
	return p.PingNContextPayloadTimeout(context.Background(), dst, n, payload, timeout, opts...)
}

// PingNTimeout is like PingNPayloadTimeout, but wuth no payload.
func (p *Pinger) PingNTimeout(dst net.IP, n int, timeout time.Duration,
	opts ...unixx.WSockOpt) (Replies, error) {
	return p.PingNContextPayloadTimeout(context.Background(), dst, n, nil, timeout, opts...)
}

// PingNPayloadInterval is the same as PingNPayloadTimeoutInterval, but with background
// context, so it tries to ping exactly n times.
func (p *Pinger) PingNPayloadInterval(dst net.IP, n int, payload []byte,
	interval time.Duration, opts ...unixx.WSockOpt) (Replies, error) {
	return p.PingNContextPayloadInterval(context.Background(), dst, n, payload, interval, opts...)
}

// PingNInterval is like PingNPayloadInterval, but with no payload.
func (p *Pinger) PingNInterval(dst net.IP, n int, interval time.Duration,
	opts ...unixx.WSockOpt) (Replies, error) {
	return p.PingNPayloadInterval(dst, n, nil, interval, opts...)
}

// PingNPayload is the same as PingNContextPayload, but with background context,
// so it tries to ping exactly n times.
func (p *Pinger) PingNPayload(dst net.IP, n int, payload []byte,
	opts ...unixx.WSockOpt) (Replies, error) {
	return p.PingNContextPayload(context.Background(), dst, n, payload, opts...)
}

// PingN is like PingNPayload, but with no payload
func (p *Pinger) PingN(dst net.IP, n int, opts ...unixx.WSockOpt) (Replies, error) {
	return p.PingNPayload(dst, n, nil, opts...)
}

func checkIntervalTimeout(interval, timeout time.Duration) {
	if !(0 < timeout && timeout <= interval) {
		panic("timeout should be in range (0, interval]")
	}
}
