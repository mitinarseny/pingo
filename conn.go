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
	"golang.org/x/net/ipv6"
)

// sendMsg sends given ICMP message to given destination
func (p *Pinger) sendMsg(dst net.IP, msg *icmp.Message) error {
	b, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	_, err = p.c.WriteToUDP(b, &net.UDPAddr{
		IP: dst,
	})
	return err
}

// sendEcho sends given ICMP Echo request to given destination
func (p *Pinger) sendEcho(dst net.IP, echo *icmp.Echo) error {
	var typ icmp.Type
	if dst.To4() != nil {
		typ = ipv4.ICMPTypeEcho
	} else {
		typ = ipv6.ICMPTypeEchoRequest
	}
	return p.sendMsg(dst, &icmp.Message{
		Type: typ,
		Body: echo,
	})
}

// send sends an ICMP Echo Request with given sequence number to given
// destination
func (p *Pinger) send(dst net.IP, seq uint16) error {
	return p.sendEcho(dst, &icmp.Echo{
		Seq: int(seq),
	})
}

// recv receives an packet into given buff and returns number of bytes read
// and the address, which the packet came from.
// readTimeout is used to set read deadline on the socket, so the recv would
// return as soon as context is done with a maximum delay of this timeout.
// Zero readTimeout meansthat the recv call would block until first ,
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
					return n, nil, ctx.Err()
				default:
					continue
				}
			}
			return n, nil, err
		}
		return n, &net.IPAddr{
			IP:   addr.IP,
			Zone: addr.Zone,
		}, nil
	}
}

// recvEcho returns first encountered ICMP Echo Reply packet.
func (p *Pinger) recvEcho(ctx context.Context, buff []byte, readTimeout time.Duration) (echo *icmp.Echo, from *net.IPAddr, err error) {
	for {
		n, from, err := p.recv(ctx, buff, readTimeout)
		if err != nil {
			return nil, nil, err
		}
		msg, err := icmp.ParseMessage(p.proto, buff[:n])
		if err != nil {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok ||
			(p.proto == ipv4.ICMPTypeEchoReply.Protocol() && msg.Type != ipv4.ICMPTypeEchoReply) ||
			(p.proto == ipv6.ICMPTypeEchoReply.Protocol() && msg.Type != ipv6.ICMPTypeEchoReply) {
			// Drop the packet since the msg is not an echo reply
			continue
		}
		return echo, from, nil
	}
}
