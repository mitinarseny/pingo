package ping

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Pinger struct {
	c4 *ipv4.PacketConn
	c6 *ipv6.PacketConn

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
// Close() should be called after Listen() returns.
func New(laddr *net.UDPAddr, dst net.IP) (*Pinger, error) {
	c, proto, err := newConn(laddr, dst)
	if err != nil {
		return nil, err
	}
	// TODO: set icmp filter

	return &Pinger{
		c4:    ipv4.NewPacketConn(c),
		c6:    ipv6.NewPacketConn(c),
		seqs:  newSequences(),
		proto: proto,
	}, nil
}

// Close releases resources allocated for Pinger.
// In particular, it closes the underlying socket.
func (p *Pinger) Close() error {
	if p.c4 != nil {
		return p.c4.Close()
	}
	return p.c6.Close()
}

// Listen handles receiving of incomming replies and routes them into calling
// Pinger.Ping* method, so *no* Pinger.Ping*() methods should be called before
// Listen and after it returns.
//
// msgBuffSize is a size of buffer for receiving incoming packets.
//
// NOTE: It is a blocking call, so it should be run as a separate goroutine.
// It returns a non-nil error if context is done or an error occured
// while receiving on sokcet.
func (p *Pinger) Listen(ctx context.Context, msgBuffSize int) error {
	if msgBuffSize == 0 {
		panic("zero buffer size")
	}
	if p.c4 != nil {
		return p.listen4(ctx, msgBuffSize)
	}
	return p.listen6(ctx, msgBuffSize)
}

// PingContextPayload sends one ICMP Echo Request to given destination with
// given payload and waits for the reply until the given context is done.
// On success, it returns the round trip time. Otherwise, it returns an error
// occured while sending on underlying socket or ctx.Err()
func (p *Pinger) PingContextPayload(ctx context.Context, dst net.IP, payload []byte) (rtt time.Duration, data []byte, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	seq, ch, err := p.seqs.add(ctx, dst)
	if err != nil {
		return 0, nil, err
	}
	defer p.seqs.free(seq)

	if err := p.sendSeq(seq, dst, payload); err != nil {
		return 0, nil, err
	}
	sentAt := time.Now()

	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case rep := <-ch:
		return rep.receivedAt.Sub(sentAt), rep.payload, rep.err
	}
}

// PingContext is like PingContextPayload, but with no payload.
func (p *Pinger) PingContext(ctx context.Context, dst net.IP) (rtt time.Duration, err error) {
	rtt, _, err = p.PingContextPayload(ctx, dst, nil)
	return rtt, err
}

// PingPayload is like PingContextPayload, but with background context.
func (p *Pinger) PingPayload(dst net.IP, payload []byte) (rtt time.Duration, err error) {
	rtt, _, err = p.PingContextPayload(context.Background(), dst, payload)
	return rtt, err
}

// Ping is like PingContext, but with background context.
func (p *Pinger) Ping(dst net.IP) (rtt time.Duration, err error) {
	return p.PingContext(context.Background(), dst)
}

// PingContextTimeoutPayload is like PingContextPayload, but it waits for the
// reply until timeout is passed or given context id done.
// Zero timeout means no timeout, so PingContextTimeout(ctx, dst, 0) is
// equialent to PingContext(ctx, dst)
func (p *Pinger) PingContextPayloadTimeout(ctx context.Context, dst net.IP,
	payload []byte, timeout time.Duration) (rtt time.Duration, data []byte, err error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return p.PingContextPayload(ctx, dst, payload)
}

// PingContextTimeout is like PingContextPayloadTimeout, but with no payload.
func (p *Pinger) PingContextTimeout(ctx context.Context, dst net.IP, timeout time.Duration) (rtt time.Duration, err error) {
	rtt, _, err = p.PingContextPayloadTimeout(ctx, dst, nil, timeout)
	return rtt, err
}

// PingPayloadTimeout is like PingContextPayloadTimeout, but with background context.
func (p *Pinger) PingPayloadTimeout(dst net.IP, payload []byte,
	timeout time.Duration) (rtt time.Duration, err error) {
	rtt, _, err = p.PingContextPayloadTimeout(context.Background(), dst, nil, timeout)
	return rtt, err
}

// PingTimeout is like PingPayloadTimeout, but no payload.
func (p *Pinger) PingTimeout(dst net.IP, timeout time.Duration) (rtt time.Duration, err error) {
	return p.PingPayloadTimeout(dst, nil, timeout)
}

type Reply struct {
	// RTT is a round trip time: the interval between sending
	// an ICMP Echo Request and receiving ICMP Echo Reply.
	RTT time.Duration

	// Data is a reply payload
	Data []byte

	// Err is an error occurred while sending ICMP Echo Request
	// or waiting for the reply
	Err error
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
	dst net.IP, interval, timeout time.Duration) <-chan Reply {
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
			rtt, data, err := p.PingContextPayloadTimeout(ctx, dst, payload, timeout)
			select {
			case <-ctx.Done():
				return
			case ch <- Reply{
				RTT:  rtt,
				Data: data,
				Err:  err,
			}:
			}
			// TODO: switch err: if non-ICMP related err -> return
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
	interval, timeout time.Duration) <-chan Reply {
	return p.PingChContextPayloadIntervalTimeout(ctx, dst, nil, interval, timeout)
}

// PingChContextPayloadInterval is the same as PingChContextIntervalTimeout,
// but with timeout equal to the interval, so it waits for reply to each request
// until interval has passed.
func (p *Pinger) PingChContextPayloadInterval(ctx context.Context, dst net.IP,
	payload []byte, interval time.Duration) <-chan Reply {
	return p.PingChContextPayloadIntervalTimeout(ctx, dst, payload, interval, interval)
}

// PingChContextInterval is like PingChContextPayloadInterval, but with no payload.
func (p *Pinger) PingChContextInterval(ctx context.Context, dst net.IP, interval time.Duration) <-chan Reply {
	return p.PingChContextIntervalTimeout(ctx, dst, interval, interval)
}

// PingChContextPayloadTimeout is the same as PingChContextPayloadIntervalTimeout,
// but echo requests are sent one by one, without waiting for interval to pass.
func (p *Pinger) PingChContextPayloadTimeout(ctx context.Context, dst net.IP,
	payload []byte, timeout time.Duration) <-chan Reply {
	return p.PingChContextPayloadIntervalTimeout(ctx, dst, payload, 0, timeout)
}

// PingChContextTimeout is like PingChContextPayloadTimeout, but with no payload.
func (p *Pinger) PingChContextTimeout(ctx context.Context, dst net.IP, timeout time.Duration) <-chan Reply {
	return p.PingChContextPayloadTimeout(ctx, dst, nil, timeout)
}

// PingChContextPayload is the same as PingChContextPayloadTimeout,
// but with no timeout, so it waits for each reply until context is done.
func (p *Pinger) PingChContextPayload(ctx context.Context, dst net.IP,
	payload []byte) <-chan Reply {
	return p.PingChContextPayloadTimeout(ctx, dst, payload, 0)
}

// PingChContext is like PingChContextPayload, but with no payload.
func (p *Pinger) PingChContext(ctx context.Context, dst net.IP) <-chan Reply {
	return p.PingChContextPayload(ctx, dst, nil)
}

// PingChPayloadTimeout is the same as PingChContextPayloadTimeout,
// but with background context, so it pings forever.
func (p *Pinger) PingChPayloadTimeout(dst net.IP, payload []byte,
	timeout time.Duration) <-chan Reply {
	return p.PingChContextPayloadTimeout(context.Background(), dst, payload, timeout)
}

// PingChTimeout is like PingChPayloadTimeout, but with no payload
func (p *Pinger) PingChTimeout(dst net.IP, timeout time.Duration) <-chan Reply {
	return p.PingChContextPayloadTimeout(context.Background(), dst, nil, timeout)
}

// PingChPayloadInterval is the same as PingChContextPayloadInterval,
// but with background timeout, so it pings forever.
func (p *Pinger) PingChPayloadInterval(dst net.IP, payload []byte,
	interval time.Duration) <-chan Reply {
	return p.PingChContextPayloadInterval(context.Background(), dst, payload, interval)
}

// PingChInterval is like PingChPayloadInterval, but with no payload.
func (p *Pinger) PingChInterval(dst net.IP, interval time.Duration) <-chan Reply {
	return p.PingChPayloadInterval(dst, nil, interval)
}

// PingChPayload is the same as PingChContextPayload, but with background
// context, so it pings forever.
func (p *Pinger) PingChPayload(dst net.IP, payload []byte) <-chan Reply {
	return p.PingChContextPayload(context.Background(), payload, dst)
}

// PingCh is like PingChPayload, but with no payload.
func (p *Pinger) PingCh(dst net.IP) <-chan Reply {
	return p.PingChPayload(dst, nil)
}

// PingNContextPayloadIntervalTimeout sends at most n ICMP Echo Requests with
// a given payload and interval (zero interval means send packets one by one
// and do not wait for interval to pass) and returns average round trip time
// for successfully received replies within the given per-reply timeout. Zero
// timeout means wait for each reply ntil context is done.
// The returned number of successfully received replies can differ from n if
// any errors encountered while sending requests and receiving replies.
// The last non-nil error is returned.
func (p *Pinger) PingNContextPayloadIntervalTimeout(ctx context.Context, dst net.IP,
	n int, payload []byte, interval, timeout time.Duration) (avgRTT time.Duration,
	success int, err error) {
	var ticker *time.Ticker
	if interval > 0 {
		checkIntervalTimeout(interval, timeout)
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	for ; n > 0; n-- {
		rtt, _, perr := p.PingContextPayloadTimeout(ctx, dst, payload, timeout)
		if perr == nil {
			avgRTT += rtt
			success++
		} else {
			err = perr
			// TODO: switch err: if non-ICMP related err -> return
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
func (p *Pinger) PingNContextPayloadInterval(ctx context.Context, dst net.IP,
	n int, payload []byte, interval time.Duration) (avgRTT time.Duration, success int, err error) {
	return p.PingNContextPayloadIntervalTimeout(ctx, dst, n, payload, interval, interval)
}

// PingNContextInterval is like PingNContextPayloadInterval, but with no payload.
func (p *Pinger) PingNContextInterval(ctx context.Context, dst net.IP,
	n int, interval time.Duration) (avgRTT time.Duration, success int, err error) {
	return p.PingNContextPayloadInterval(ctx, dst, n, nil, interval)
}

// PingNContextPayloadTimeout is the same as PingNContextPayloadIntervalTimeout,
// but echo requests are sent one by one, without waiting for interval to pass.
func (p *Pinger) PingNContextPayloadTimeout(ctx context.Context, dst net.IP,
	n int, payload []byte, timeout time.Duration) (avgRTT time.Duration,
	success int, err error) {
	return p.PingNContextPayloadIntervalTimeout(ctx, dst, n, payload, 0, timeout)
}

// PingNContextTimeout is like PingNContextPayloadTimeout, but with no payload.
func (p *Pinger) PingNContextTimeout(ctx context.Context, dst net.IP, n int,
	timeout time.Duration) (avgRTT time.Duration, success int, err error) {
	return p.PingNContextPayloadTimeout(ctx, dst, n, nil, timeout)
}

// PingNContextPayload is the same as PingNContextPayloadTimeout, but with no
// timeout, so it waits for each reply until context is done.
func (p *Pinger) PingNContextPayload(ctx context.Context, dst net.IP, n int,
	payload []byte) (avgRTT time.Duration, success int, err error) {
	return p.PingNContextPayloadTimeout(ctx, dst, n, payload, 0)
}

// PingNContext is like PingNContextPayload, but with no payload.
func (p *Pinger) PingNContext(ctx context.Context, dst net.IP, n int) (avgRTT time.Duration, success int, err error) {
	return p.PingNContextTimeout(ctx, dst, n, 0)
}

// PingNPayloadTimeout is the same as PingNContextPayloadTimeout, but with background
// context, so it tries to ping exactly n times.
func (p *Pinger) PingNPayloadTimeout(dst net.IP, n int, payload []byte,
	timeout time.Duration) (avgRTT time.Duration, success int, err error) {
	return p.PingNContextPayloadTimeout(context.Background(), dst, n, payload, timeout)
}

// PingNTimeout is like PingNPayloadTimeout, but wuth no payload.
func (p *Pinger) PingNTimeout(dst net.IP, n int, timeout time.Duration) (avgRTT time.Duration, success int, err error) {
	return p.PingNContextPayloadTimeout(context.Background(), dst, n, nil, timeout)
}

// PingNPayloadInterval is the same as PingNPayloadTimeoutInterval, but with background
// context, so it tries to ping exactly n times.
func (p *Pinger) PingNPayloadInterval(dst net.IP, n int, payload []byte,
	interval time.Duration) (avgRTT time.Duration, success int, err error) {
	return p.PingNContextPayloadInterval(context.Background(), dst, n, payload, interval)
}

// PingNInterval is like PingNPayloadInterval, but with no payload.
func (p *Pinger) PingNInterval(dst net.IP, n int, interval time.Duration) (avgRTT time.Duration, success int, err error) {
	return p.PingNPayloadInterval(dst, n, nil, interval)
}

// PingNPayload is the same as PingNContextPayload, but with background context,
// so it tries to ping exactly n times.
func (p *Pinger) PingNPayload(dst net.IP, n int, payload []byte) (
	avgRTT time.Duration, success int, err error) {
	return p.PingNContextPayload(context.Background(), dst, n, payload)
}

// PingN is like PingNPayload, but with no payload
func (p *Pinger) PingN(dst net.IP, n int) (avgRTT time.Duration, success int, err error) {
	return p.PingNPayload(dst, n, nil)
}

// send sends an ICMP Echo Request with given sequence number and payload
// to given destination
func (p *Pinger) sendSeq(seq uint16, dst net.IP, payload []byte) error {
	return p.sendEcho(&icmp.Echo{
		// ID is chosen by kernel
		Seq:  int(seq),
		Data: payload,
	}, dst)
}

// sendEcho sends given ICMP Echo request to given destination
func (p *Pinger) sendEcho(echo *icmp.Echo, dst net.IP) error {
	var typ icmp.Type
	if dst.To4() != nil {
		typ = ipv4.ICMPTypeEcho
	} else {
		typ = ipv6.ICMPTypeEchoRequest
	}
	return p.sendMsg(&icmp.Message{
		Type: typ,
		Body: echo,
	}, dst)
}

// sendMsg sends given ICMP message to given destination
func (p *Pinger) sendMsg(msg *icmp.Message, dst net.IP) error {
	b, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return p.send(b, dst)
}

func checkIntervalTimeout(interval, timeout time.Duration) {
	if !(0 < timeout && timeout <= interval) {
		panic("timeout should be in range (0, interval]")
	}
}
