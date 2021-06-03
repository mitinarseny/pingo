package ping

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func (p *Pinger) send(dst net.IP, seq uint16) error {
	return p.sendEcho(dst, &icmp.Echo{
		Seq:  int(seq),
	})
}

func (p *Pinger) sendEcho(dst net.IP, echo *icmp.Echo) error {
	return p.sendMsg(dst, &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: echo,
	})
}

func (p *Pinger) sendMsg(dst net.IP, msg *icmp.Message) error {
	b, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	_, err = p.c.WriteToUDP(b, &net.UDPAddr{
		IP:   dst,
	})
	return err
}

func (p *Pinger) recv(ctx context.Context, buff []byte, readTimeout time.Duration) (n int, from *net.IPAddr, err error) {
	for {
		if readTimeout > 0 {
			if err := p.c.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
				return 0, nil, err
			}
		}
		n, addr, err := p.c.ReadFromUDP(buff)
		if err != nil {
			if readTimeout > 0 && errors.Is(err, os.ErrDeadlineExceeded) {
				select {
				case <-ctx.Done():
					// reset read deadline for future calls
					p.c.SetReadDeadline(time.Time{})
					err = ctx.Err()
					return 0, nil, err
				default:
					continue
				}
			}
			return 0, nil, err
		}
		return n, &net.IPAddr{
			IP:   addr.IP,
			Zone: addr.Zone,
		}, nil
	}
}
