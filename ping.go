package ping

import (
	"context"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
)

type Pinger struct {
	c    *net.UDPConn
	seqs *sequences

	proto  int
	logger func(error)
}

func New(laddr, dst net.IP, logger func(error)) (*Pinger, error) {
	c, proto, err := newConn(laddr, dst)
	if err != nil {
		return nil, err
	}

	return &Pinger{
		c:      c,
		seqs:   newSequences(),
		proto:  proto,
		logger: logger,
	}, nil
}

func (p *Pinger) SetTTL(ttl uint8) error {
	c, err := p.c.SyscallConn()
	if err != nil {
		return err
	}
	c.Control(func(fd uintptr) {
		err = os.NewSyscallError("setsockopt", syscall.SetsockoptByte(int(fd), syscall.SOL_IP, syscall.IP_TTL, ttl))
	})
	return err
}

func (p *Pinger) Listen(ctx context.Context, readTimeout time.Duration) error {
	buff := make([]byte, 1500)
	for {
		n, from, err := p.recv(ctx, buff, readTimeout)
		if err != nil {
			return err
		}
		receivedAt := time.Now()

		msg, err := icmp.ParseMessage(p.proto, buff[:n])
		if err != nil {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		pend := p.seqs.get(uint16(echo.Seq))
		if pend == nil || !from.IP.Equal(pend.dst){
			// Drop the reply in following cases:
			//   * we did not send the echo request to which the reply came
			//   * sender gave up waiting for the reply
			//   * the echo reply came from the address, which is different from
			//     the destination address, to which the request was sent
			//   * the error reply came for the request, which destination
			//     address is different from the address, which we sent the
			//     request to
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-pend.ctx.Done():
			// sender gave up waiting for the reply
		case pend.ch <- receivedAt.Sub(pend.sentAt):
			close(pend.ch)
		}
	}
}

func (p *Pinger) Close() error {
	return p.c.Close()
}

func (p *Pinger) log(err error) {
	if p.logger == nil {
		return
	}
	p.logger(err)
}

func (p *Pinger) PingContext(ctx context.Context, dst net.IP) (rtt time.Duration, err error) {
	seq, ch, err := p.seqs.add(ctx, dst, time.Now())
	if err != nil {
		return 0, err
	}
	defer p.seqs.free(seq)
	// defer p.seqs.pop(seq)

	if err := p.send(dst, seq); err != nil {
		return 0, err
	}

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case rtt = <-ch:
		return rtt, nil
	}
}

func (p *Pinger) Ping(dst net.IP) (rtt time.Duration, err error) {
	return p.PingContext(context.Background(), dst)
}

func (p *Pinger) PingContextTimeout(ctx context.Context, dst net.IP, timeout time.Duration) (rtt time.Duration, err error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return p.PingContext(ctx, dst)
}

func (p *Pinger) PingTimeout(dst net.IP, timeout time.Duration) (rtt time.Duration, err error) {
	return p.PingContextTimeout(context.Background(), dst, timeout)
}

type Reply struct {
	RTT time.Duration
	Err error
}

func (p *Pinger) PingChContextIntervalTimeout(ctx context.Context, dst net.IP, interval, timeout time.Duration) <-chan Reply {
	checkIntervalTimeout(interval, timeout)
	ch := make(chan Reply)
	go func() {
		defer close(ch)

		var ticker *time.Ticker
		if interval > 0 {
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
			if ticker != nil {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					continue
				}
			}
		}
	}()
	return ch
}

func (p *Pinger) PingChContextInterval(ctx context.Context, dst net.IP, interval time.Duration) <-chan Reply {
	return p.PingChContextIntervalTimeout(ctx, dst, interval, interval)
}

func (p *Pinger) PingChContextTimeout(ctx context.Context, dst net.IP, timeout time.Duration) <-chan Reply {
	return p.PingChContextIntervalTimeout(ctx, dst, 0, timeout)
}

func (p *Pinger) PingChContext(ctx context.Context, dst net.IP) <-chan Reply {
	return p.PingChContextTimeout(ctx, dst, 0)
}

func (p *Pinger) PingCh(dst net.IP) <-chan Reply {
	return p.PingChContext(context.Background(), dst)
}

func (p *Pinger) PingChTimeout(dst net.IP, timeout time.Duration) <-chan Reply {
	return p.PingChContextTimeout(context.Background(), dst, timeout)
}

func (p *Pinger) PingChInterval(dst net.IP, interval time.Duration) <-chan Reply {
	return p.PingChContextInterval(context.Background(), dst, interval)
}

func (p *Pinger) PingNContextIntervalTimeout(ctx context.Context, dst net.IP, n int, intervall, timeout time.Duration) (avgRTT time.Duration, sent int, err error) {
	checkIntervalTimeout(intervall, timeout)

	var ticker *time.Ticker
	if intervall > 0 {
		ticker = time.NewTicker(intervall)
		defer ticker.Stop()
	}
	for ; n > 0; n-- {
		rtt, perr := p.PingContextTimeout(ctx, dst, timeout)
		if perr == nil {
			avgRTT += rtt
			sent++
		} else {
			err = perr
		}
		if ticker != nil {
			select {
			case <-ctx.Done():
				err = ctx.Err()
				goto breakLoop
			case <-ticker.C:
				continue
			}
		}
	}
breakLoop:
	if sent > 0 {
		avgRTT /= time.Duration(sent)
	}
	return
}

func (p *Pinger) PingNContextInterval(ctx context.Context, dst net.IP, n int, interval time.Duration) (avgRTT time.Duration, sent int, err error) {
	return p.PingNContextIntervalTimeout(ctx, dst, n, interval, interval)
}

func (p *Pinger) PingNContextTimeout(ctx context.Context, dst net.IP, n int, timeout time.Duration) (avgRTT time.Duration, sent int, err error) {
	return p.PingNContextIntervalTimeout(ctx, dst, n, 0, timeout)
}

func (p *Pinger) PingNContext(ctx context.Context, dst net.IP, n int) (avgRTT time.Duration, sent int, err error) {
	return p.PingNContextTimeout(ctx, dst, n, 0)
}

func (p *Pinger) PingN(dst net.IP, n int) (avgRTT time.Duration, sent int, err error) {
	return p.PingNContext(context.Background(), dst, n)
}

func (p *Pinger) PingNTimeout(dst net.IP, n int, timeout time.Duration) (avgRTT time.Duration, sent int, err error) {
	return p.PingNContextTimeout(context.Background(), dst, n, timeout)
}

func (p *Pinger) PingNInterval(dst net.IP, n int, interval time.Duration) (avgRTT time.Duration, sent int, err error) {
	return p.PingNContextInterval(context.Background(), dst, n, interval)
}

func checkIntervalTimeout(interval, timeout time.Duration) {
	if interval > 0 && (timeout == 0 || timeout > interval) {
		panic("timeout should not be zero or greater than interval")
	}
}
