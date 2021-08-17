package ping

import (
	"context"
	// "errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// newConn returns a new udp connection with given local and destination addresses.
// laddr should be a valid IP address, while dst could be nil.
// Non-nil dst means that ICMP packets could be sent to and received from
// only given address, pinging different address would result in error.
// The returner proto is ICMP protocol number.
func newConn(laddr *net.UDPAddr, dst net.IP) (conn *net.UDPConn, proto int, err error) {
	if laddr == nil {
		laddr = new(net.UDPAddr)
	}
	if laddr.IP == nil {
		laddr.IP = net.IPv4zero
	}
	var family int
	if laddr.IP.To4() != nil {
		family, proto = unix.AF_INET, ipv4.ICMPTypeEcho.Protocol()
	} else {
		family, proto = unix.AF_INET6, ipv6.ICMPTypeEchoRequest.Protocol()
	}
	s, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, 0, os.NewSyscallError("socket", err)
	}
	if err := unix.SetNonblock(s, true); err != nil {
		unix.Close(s)
		return nil, 0, os.NewSyscallError("setnonblock", err)
	}
	if err := unix.SetsockoptInt(s, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
		unix.Close(s)
		return nil, 0, os.NewSyscallError("setsockopt", err)
	}

	if err := unix.Bind(s, sockaddr(laddr)); err != nil {
		unix.Close(s)
		return nil, 0, os.NewSyscallError("bind", err)
	}
	if dst != nil {
		if err := unix.Connect(s, sockaddr(&net.UDPAddr{IP: dst})); err != nil {
			unix.Close(s)
			return nil, 0, os.NewSyscallError("connect", err)
		}
	}
	f := os.NewFile(uintptr(s), "datagram-oriented icmp")
	c, cerr := net.FilePacketConn(f)
	if err := f.Close(); err != nil {
		return nil, 0, err
	}
	return c.(*net.UDPConn), proto, cerr
}

// SetTTL with non-zero sets the given Time-to-Live on all outgoing IP packets.
// Pass ttl 0 to get the current value.
func (p *Pinger) SetTTL(ttl uint8) (uint8, error) {
	c, err := p.c.SyscallConn()
	if err != nil {
		return 0, err
	}
	c.Control(func(fd uintptr) {
		if ttl == 0 {
			var t int
			t, err = unix.GetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TTL)
			ttl = uint8(t)
			err = os.NewSyscallError("getsockopt", err)
		} else {
			err = os.NewSyscallError("setsockopt",
				unix.SetsockoptByte(int(fd), unix.SOL_IP, unix.IP_TTL, ttl))
		}
	})
	return ttl, err
}

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
func (p *Pinger) send(dst net.IP, seq uint16, payload []byte) error {
	return p.sendEcho(dst, &icmp.Echo{
		Seq:  int(seq),
		Data: payload,
	})
}

// recv receives an packet into given buff and returns number of bytes read
// and the address, which the packet came from.
// readTimeout is used to set read deadline on the socket, so the recv would
// return as soon as context is done with a maximum delay of this timeout.
// Zero readTimeout means that the recv call would block until first packet received.
func (p *Pinger) recv(ctx context.Context, buff, oob []byte, readTimeout time.Duration) (n, oobn int, from *net.IPAddr, err error) {
	for {
		// if readTimeout > 0 {
		// 	if err := p.c.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		// 		return 0, 0, nil, err
		// 	}
		// }
		// TODO: unix.SO_RECVTIMEO
		sc, err := p.c.SyscallConn()
		if err != nil {
			// TODO
			return 0, 0, nil, err
		}
		// n, oobn, flags, sa, err :=
		var (
			n, oobn, flags int
			sa             unix.Sockaddr
			rerr           error
		)
		// net.DialUDP
		// ipv4.NewPacketConn().ReadBatch
		if err := sc.Read(func(fd uintptr) (done bool) {
			for {
				fmt.Println("trying to recvmsg")
				n, oobn, flags, sa, rerr = unix.Recvmsg(int(fd), buff, oob, unix.MSG_ERRQUEUE)
				switch rerr {
				case unix.EINTR:
					continue
				case unix.EAGAIN:
					fmt.Println("try again")
					return false
				default:
					fmt.Printf("exiting syscallConn.Read(): %s, flags: %d\n", rerr, flags)
					return true
				}
			}

			// // TODO: recvmmsg
			// n, oobn, flags, sa, rerr = unix.Recvmsg(int(fd), buff, oob, unix.MSG_ERRQUEUE)
			// switch rerr {
			// case unix.EINTR, unix.EAGAIN:
			// 	fmt.Printf("rawRead err inside func: %s\n", rerr)
			// 	return false
			// default:
			// 	fmt.Printf("exiting SyscallConn.Read(): %s, flags: %d\n", rerr, flags)
			// 	return true
			// }
		}); err != nil {
			// if readTimeout > 0 && errors.Is(err, os.ErrDeadlineExceeded) {
			// 	select {
			// 	case <-ctx.Done():
			// 		// reset read deadline for future calls
			// 		// p.c.SetReadDeadline(time.Time{})
			// 		return n, oobn, nil, ctx.Err()
			// 	default:
			// 		fmt.Println("read deadline exceeded, but context not done")
			// 		continue
			// 	}
			// }
			fmt.Printf("rawRead err: %s\n", err)
			return n, oobn, nil, err
		}
		fmt.Println("rawRead returned without err")
		if rerr != nil {
			// TODO
			fmt.Printf("rerr: %s\n", rerr)
			continue
		}
		if oobn <= 0 {
			fmt.Printf("oobn: %d\n", oobn)
			continue
		}

		// var cm
		switch sa := sa.(type) {
		case *unix.SockaddrInet4:
			from = &net.IPAddr{IP: sa.Addr[:]}
		case *unix.SockaddrInet6:
			from = &net.IPAddr{IP: sa.Addr[:]}
		}
		return n, oobn, from, rerr
	}
}

// recvEcho returns first encountered ICMP Echo Reply packet.
func (p *Pinger) recvEcho(ctx context.Context, buff, oob []byte, readTimeout time.Duration) (echo *icmp.Echo, wasTo *net.IPAddr, err error) {
	for {
		n, oobn, from, err := p.recv(ctx, buff, oob, readTimeout)
		fmt.Printf("recv: n: %d, oobn: %d, from: %s, err: %s\n", n, oobn, from, err)
		if err != nil { // TODO: will oob be 0 if no errors?
			fmt.Printf("err: %s\n", err)
			return nil, nil, err
		}
		if oobn <= 0 {
			fmt.Printf("oobn <= 0\n")
			continue
		}
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		if cmsghdr.Level != unix.IPPROTO_IP {
			fmt.Println("not ip level")
			// this isn't an IP level message
			continue
		}
		se := (*unix.SockExtendedErr)(unsafe.Pointer(&oob[unix.SizeofCmsghdr]))
		fmt.Printf("recv sock_extended_err: %#v, errno: %s\n", se, unix.ErrnoName(syscall.Errno(se.Errno)))
		switch se.Origin {
		case unix.SO_EE_ORIGIN_ICMP:
		case unix.SO_EE_ORIGIN_ICMP6:
		default:
			fmt.Printf("origin: %d\n", se.Origin)
			continue
		}
		// switch sa := sa.(type) {
		// case *syscall.SockaddrInet4:
		// 	var cm ipv4.ControlMessage
		// 	if err := cm.Parse(oob[:oobn]); err != nil {
		// 		continue
		// 	}
		// case *syscall.SockaddrInet6:
		// 	var cm ipv6.ControlMessage
		// 	if err := cm.Parse(oob[:oobn]); err != nil {
		//
		// 	}
		// }

		msg, err := icmp.ParseMessage(p.proto, buff[:n])
		if err != nil {
			fmt.Printf("unable to parse icmp: %s\n", err)
			continue
		}
		if echo, ok := msg.Body.(*icmp.Echo); ok {
			fmt.Printf("recv is echo: %#v\n", echo)
			return echo, from, nil
		}
		fmt.Println("ok")

		var (
			data []byte
			perr error
		)
		switch body := msg.Body.(type) {
		case *icmp.DstUnreach:
			data = body.Data
			perr = DestinationUnreachableError{
				From: from,
				Code: DstUnreachableCode(msg.Code),
			}
		case *icmp.TimeExceeded:
			data = body.Data
			perr = TimeExceeded{From: from}
		default:
			fmt.Println("not ok")
			// unsupported message type
			continue
		}
		var (
			dst       net.IP
			innerBody []byte
		)
		switch p.proto {
		case ipv4.ICMPTypeDestinationUnreachable.Protocol():
			h, err := ipv4.ParseHeader(data)
			if err != nil || h.Protocol != p.proto {
				fmt.Printf("not ours proto: %d\n", h.Protocol)
				continue
			}
			dst = h.Dst
			innerBody = data[h.Len:]
		case ipv6.ICMPTypeDestinationUnreachable.Protocol():
			h, err := ipv6.ParseHeader(data)
			if err != nil || h.NextHeader != p.proto {
				continue
			}
			dst = h.Dst
			innerBody = data[ipv6.HeaderLen:]
		}
		innerMsg, err := icmp.ParseMessage(p.proto, innerBody)
		if err != nil {
			fmt.Printf("unable to parse inner msg: %s\n", err)
			continue
		}
		innerEcho, ok := innerMsg.Body.(*icmp.Echo)
		if !ok {
			fmt.Printf("inner msg is not echo: %#v\n", innerMsg.Body)
			continue
		}
		return innerEcho, &net.IPAddr{IP: dst}, perr
	}
}

// sockaddr converts *net.UDPAddr to syscall.Sockaddr
func sockaddr(addr *net.UDPAddr) unix.Sockaddr {
	if ip4 := addr.IP.To4(); ip4 != nil {
		sa := unix.SockaddrInet4{
			Port: addr.Port,
		}
		copy(sa.Addr[:], ip4)
		return &sa
	}
	sa := unix.SockaddrInet6{
		Port: addr.Port,
	}
	copy(sa.Addr[:], addr.IP.To16())
	return &sa
}
