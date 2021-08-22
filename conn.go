package ping

import (
	"context"
	"errors"
	"time"
	"unsafe"

	"net"
	"os"

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

func newConn(laddr *net.UDPAddr, dst net.IP) (conn net.PacketConn, proto int, err error) {
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
	// TODO
	// if err := unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1); err != nil {
	// 	unix.Close(s)
	// 	return nil, 0, os.NewSyscallError("setsockopt", err)
	// }

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
	if cerr != nil {
		return nil, 0, cerr
	}
	if err := c.SetReadDeadline(time.Now()); err != nil {
		c.Close()
		return nil, 0, err
	}
	return c, proto, nil
}

// TTL returns current TTL set for outgoing packages
func (p *Pinger) TTL() (uint8, error) {
	var (
		ttl int
		err error
	)
	if p.c4 != nil {
		ttl, err = p.c4.TTL()
	} else {
		ttl, err = p.c6.HopLimit()
	}
	return uint8(ttl), err
}

// SetTTL with non-zero sets the given Time-to-Live on all outgoing IP packets.
// Pass ttl 0 to get the current value.
func (p *Pinger) SetTTL(ttl uint8) error {
	if p.c4 != nil {
		return p.c4.SetTTL(int(ttl))
	}
	return p.c6.SetHopLimit(int(ttl))
}

// send sends buffer to given destination
func (p *Pinger) send(b []byte, dst net.IP) (err error) {
	dstAddr := net.IPAddr{IP: dst}
	if p.c4 != nil {
		_, err = p.c4.WriteTo(b, nil, &dstAddr)
	} else {
		_, err = p.c6.WriteTo(b, nil, &dstAddr)
	}
	return err
}

func (p *Pinger) listen4(ctx context.Context, msgBuffSize int) error {
	// unlock for reading
	if err := p.c4.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan udpPacket) // TODO: bufferred chan?
	// go p.dispatcher(ctx, ch)
	go func() {
		<-ctx.Done()
		_ = p.c4.SetReadDeadline(time.Now())
	}()

	err := p.loop4(ctx, ch, msgBuffSize)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		err = ctx.Err()
	}
	return err
}

type udpPacket struct {
	src  *net.UDPAddr
	data []byte
}

// func (p *Pinger) dispatcher(ctx context.Context, ch <-chan udpPacket) {
// 	for pkt := range ch {
// 		_ = p.dispatch(ctx, pkt.src.IP, pkt.data)
// 	}
// }

func (p *Pinger) loop4(ctx context.Context, ch chan<- udpPacket, msgBuffSize int) error {
	defer close(ch)
	const (
		buffSize = 1500
	) // TODO: custom?
	ms := make([]ipv4.Message, msgBuffSize) // TODO: size
	for i := range ms {
		ms[i].Buffers = [][]byte{make([]byte, 1500)}
		ms[i].OOB = make([]byte, 1500)
	}
	// icmpBuff := make([]byte, 1500) // TODO: custom size for receiving payload
	for {
		n, err := p.c4.ReadBatch(ms, 0)
		if errors.Is(err, unix.EHOSTUNREACH) {
			// there should be at least one ICMP error
			n, err = p.c4.ReadBatch(ms, unix.MSG_ERRQUEUE|unix.MSG_WAITFORONE)
		}
		if err != nil {
			return err
		}
		for _, m := range ms[:n] {
			if m.Addr == nil {
				continue
			}
			src, ok := m.Addr.(*net.UDPAddr)
			if !ok {
				continue
			}
			msg, err := icmp.ParseMessage(p.proto, m.Buffers[0][:m.N])
			if err != nil {
				// not an ICMP message
				continue
			}
			echo, ok := msg.Body.(*icmp.Echo)
			if !ok {
				// not ICMP echo
				continue
			}
			var icmpErr error
			if m.Flags&unix.MSG_ERRQUEUE != 0 {
				cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(&m.OOB[0]))
				if !(cmsghdr.Level != unix.IPPROTO_IP || cmsghdr.Type == unix.IP_RECVERR) {
					// this isn't an IP level or error type message
					// TODO: iter like CMSG_NXTHDR
					continue
				}
				se := (*unix.SockExtendedErr)(unsafe.Pointer(&m.OOB[unix.SizeofCmsghdr]))
				switch se.Origin {
				case unix.SO_EE_ORIGIN_ICMP:
					sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(&m.OOB[unix.SizeofCmsghdr+unsafe.Sizeof(*se)]))
					switch se.Type {
					case uint8(ipv4.ICMPTypeDestinationUnreachable):
						icmpErr = DestinationUnreachableError{
							From: sa.Addr[:],
							Code: DstUnreachableCode(se.Code),
						}
					case uint8(ipv4.ICMPTypeTimeExceeded):
						icmpErr = TimeExceeded{From: sa.Addr[:]}
					default:
						// unsupported ICMP error message type
						continue
					}
				case unix.SO_EE_ORIGIN_ICMP6:
					sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(&m.OOB[unix.SizeofCmsghdr+unsafe.Sizeof(*se)]))
					switch se.Type {
					case uint8(ipv6.ICMPTypeDestinationUnreachable):
						icmpErr = DestinationUnreachableError{
							From: sa.Addr[:],
							Code: DstUnreachableCode(se.Code),
						}
					case uint8(ipv6.ICMPTypeTimeExceeded):
						icmpErr = TimeExceeded{From: sa.Addr[:]}
					default:
						// unsupported ICMP error message type
						continue
					}
				default:
					// not ICMP error message
					continue
				}
			}
			if err := p.dispatchEcho(ctx, src.IP, echo, icmpErr); err != nil {
				// TODO: context error?
				continue
			}
		}
	}
}

func (p *Pinger) listen6(ctx context.Context, buffSize int) error {
	// TODO
	return nil
}

// func (p *Pinger) dispatch(ctx context.Context, src net.IP, data []byte) error {
// 	msg, err := icmp.ParseMessage(p.proto, data)
// 	if err != nil {
// 		return fmt.Errorf("unable to parse ICMP message: %w", err)
// 	}
// 	if echo, ok := msg.Body.(*icmp.Echo); ok {
// 		return p.dispatchEcho(ctx, src, echo, nil)
// 	}
//
// 	var icmpErr error
// 	// data will be reassigned to outer ICMP message payload
// 	switch body := msg.Body.(type) {
// 	case *icmp.DstUnreach:
// 		data = body.Data
// 		icmpErr = DestinationUnreachableError{
// 			From: &net.UDPAddr{IP: src},
// 			Code: DstUnreachableCode(msg.Code),
// 		}
// 	case *icmp.TimeExceeded:
// 		data = body.Data
// 		icmpErr = TimeExceeded{From: &net.UDPAddr{IP: src}}
// 	default:
// 		return fmt.Errorf("unsupported ICMP message type: %s", msg.Type)
// 	}
//
// 	// data will be reassigned to inner IP payload
// 	// src will be reasssigned to inner IP destination
// 	switch msg.Type.(type) {
// 	case ipv4.ICMPType:
// 		h, err := ipv4.ParseHeader(data)
// 		if err != nil {
// 			return fmt.Errorf("unable to parse inner IPv4 header: %w", err)
// 		}
// 		src = h.Dst
// 		data = data[h.Len:]
// 		if len(data) > h.TotalLen {
// 			data = data[:h.TotalLen]
// 		}
// 	case ipv6.ICMPType:
// 		h, err := ipv6.ParseHeader(data)
// 		if err != nil {
// 			return fmt.Errorf("unable to parse inner IPv6 header: %w", err)
// 		}
// 		src = h.Dst
// 		data = data[ipv6.HeaderLen:]
// 		if len(data) > h.PayloadLen {
// 			data = data[:h.PayloadLen]
// 		}
// 	}
// 	innerMsg, err := icmp.ParseMessage(p.proto, data)
// 	if err != nil {
// 		return fmt.Errorf("unable to parse inner ICMP message: %w", err)
// 	}
// 	innerEcho, ok := innerMsg.Body.(*icmp.Echo)
// 	if !ok {
// 		return fmt.Errorf("expected inner message to be ICMP Echo, but got %s", innerMsg.Type)
// 	}
// 	return p.dispatchEcho(ctx, src, innerEcho, icmpErr)
// }

func (p *Pinger) dispatchEcho(ctx context.Context, dst net.IP,
	echo *icmp.Echo, icmpErr error) error {
	return p.dispatchSeq(ctx, dst, uint16(echo.Seq), echo.Data, icmpErr)
}

func (p *Pinger) dispatchSeq(ctx context.Context, dst net.IP, seq uint16,
	payload []byte, icmpErr error) error {
	receivedAt := time.Now() // TODO: socket timestamps
	pend := p.seqs.get(seq)
	if pend == nil || !dst.Equal(pend.dst) {
		// Drop the reply in following cases:
		//   * we did not send the echo request, which the reply came to
		//   * sender gave up waiting for the reply
		//   * the echo reply came from the address, which is different from
		//     the destination address, which the request was sent to
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-pend.ctx.Done():
		// sender gave up waiting for the reply
		return nil
	// TODO: do not send anything is context is done
	// TODO: and close the reply chan
	case pend.reply <- reply{
		receivedAt: receivedAt,
		payload:    payload,
		err:        icmpErr,
	}:
		return nil
	}
}

// recv receives an packet into given buff and returns number of bytes read
// and the address, which the packet came from.
// readTimeout is used to set read deadline on the socket, so the recv would
// return as soon as context is done with a maximum delay of this timeout.
// Zero readTimeout means that the recv call would block until first packet received.
// func (p *Pinger) recv(ctx context.Context, buff, oob []byte, readTimeout time.Duration) (n, oobn int, from *net.IPAddr, err error) {
// 	for {
// 		// if readTimeout > 0 {
// 		// 	if err := p.c.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
// 		// 		return 0, 0, nil, err
// 		// 	}
// 		// }
// 		// TODO: unix.SO_RECVTIMEO
// 		sc, err := p.c4.SyscallConn()
// 		if err != nil {
// 			// TODO
// 			return 0, 0, nil, err
// 		}
// 		// n, oobn, flags, sa, err :=
// 		var (
// 			n, oobn, flags int
// 			sa             unix.Sockaddr
// 			rerr           error
// 		)
// 		// net.DialUDP
// 		// ipv4.NewPacketConn().ReadBatch
// 		if err := sc.Read(func(fd uintptr) (done bool) {
// 			for {
// 				fmt.Println("trying to recvmsg")
// 				n, oobn, flags, sa, rerr = unix.Recvmsg(int(fd), buff, oob, unix.MSG_ERRQUEUE)
// 				switch rerr {
// 				case unix.EINTR:
// 					continue
// 				case unix.EAGAIN:
// 					fmt.Println("try again")
// 					return false
// 				default:
// 					fmt.Printf("exiting syscallConn.Read(): %s, flags: %d\n", rerr, flags)
// 					return true
// 				}
// 			}
//
// 			// // TODO: recvmmsg
// 			// n, oobn, flags, sa, rerr = unix.Recvmsg(int(fd), buff, oob, unix.MSG_ERRQUEUE)
// 			// switch rerr {
// 			// case unix.EINTR, unix.EAGAIN:
// 			// 	fmt.Printf("rawRead err inside func: %s\n", rerr)
// 			// 	return false
// 			// default:
// 			// 	fmt.Printf("exiting SyscallConn.Read(): %s, flags: %d\n", rerr, flags)
// 			// 	return true
// 			// }
// 		}); err != nil {
// 			// if readTimeout > 0 && errors.Is(err, os.ErrDeadlineExceeded) {
// 			// 	select {
// 			// 	case <-ctx.Done():
// 			// 		// reset read deadline for future calls
// 			// 		// p.c.SetReadDeadline(time.Time{})
// 			// 		return n, oobn, nil, ctx.Err()
// 			// 	default:
// 			// 		fmt.Println("read deadline exceeded, but context not done")
// 			// 		continue
// 			// 	}
// 			// }
// 			fmt.Printf("rawRead err: %s\n", err)
// 			return n, oobn, nil, err
// 		}
// 		fmt.Println("rawRead returned without err")
// 		if rerr != nil {
// 			// TODO
// 			fmt.Printf("rerr: %s\n", rerr)
// 			continue
// 		}
// 		if oobn <= 0 {
// 			fmt.Printf("oobn: %d\n", oobn)
// 			continue
// 		}
//
// 		// var cm
// 		switch sa := sa.(type) {
// 		case *unix.SockaddrInet4:
// 			from = &net.IPAddr{IP: sa.Addr[:]}
// 		case *unix.SockaddrInet6:
// 			from = &net.IPAddr{IP: sa.Addr[:]}
// 		}
// 		return n, oobn, from, rerr
// 	}
// }

// recvEcho returns first encountered ICMP Echo Reply packet.
// func (p *Pinger) recvEcho(ctx context.Context, buff, oob []byte, readTimeout time.Duration) (echo *icmp.Echo, wasTo *net.IPAddr, err error) {
// 	for {
// 		n, oobn, from, err := p.recv4(ctx)
// 		fmt.Printf("recv: n: %d, oobn: %d, from: %s, err: %s\n", n, oobn, from, err)
// 		if err != nil { // TODO: will oob be 0 if no errors?
// 			fmt.Printf("err: %s\n", err)
// 			return nil, nil, err
// 		}
// 		if oobn <= 0 {
// 			fmt.Printf("oobn <= 0\n")
// 			continue
// 		}
// 		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
// 		if cmsghdr.Level != unix.IPPROTO_IP {
// 			fmt.Println("not ip level")
// 			// this isn't an IP level message
// 			continue
// 		}
// 		se := (*unix.SockExtendedErr)(unsafe.Pointer(&oob[unix.SizeofCmsghdr]))
// 		fmt.Printf("recv sock_extended_err: %#v, errno: %s\n", se, unix.ErrnoName(syscall.Errno(se.Errno)))
// 		switch se.Origin {
// 		case unix.SO_EE_ORIGIN_ICMP:
// 		case unix.SO_EE_ORIGIN_ICMP6:
// 		default:
// 			fmt.Printf("origin: %d\n", se.Origin)
// 			continue
// 		}
// 		// switch sa := sa.(type) {
// 		// case *syscall.SockaddrInet4:
// 		// 	var cm ipv4.ControlMessage
// 		// 	if err := cm.Parse(oob[:oobn]); err != nil {
// 		// 		continue
// 		// 	}
// 		// case *syscall.SockaddrInet6:
// 		// 	var cm ipv6.ControlMessage
// 		// 	if err := cm.Parse(oob[:oobn]); err != nil {
// 		//
// 		// 	}
// 		// }
//
// 		msg, err := icmp.ParseMessage(p.proto, buff[:n])
// 		if err != nil {
// 			fmt.Printf("unable to parse icmp: %s\n", err)
// 			continue
// 		}
// 		if echo, ok := msg.Body.(*icmp.Echo); ok {
// 			fmt.Printf("recv is echo: %#v\n", echo)
// 			return echo, from, nil
// 		}
// 		fmt.Println("ok")
//
// 		var (
// 			data []byte
// 			perr error
// 		)
// 		switch body := msg.Body.(type) {
// 		case *icmp.DstUnreach:
// 			data = body.Data
// 			perr = DestinationUnreachableError{
// 				From: from,
// 				Code: DstUnreachableCode(msg.Code),
// 			}
// 		case *icmp.TimeExceeded:
// 			data = body.Data
// 			perr = TimeExceeded{From: from}
// 		default:
// 			fmt.Println("not ok")
// 			// unsupported message type
// 			continue
// 		}
// 		var (
// 			dst       net.IP
// 			innerBody []byte
// 		)
// 		switch p.proto {
// 		case ipv4.ICMPTypeDestinationUnreachable.Protocol():
// 			h, err := ipv4.ParseHeader(data)
// 			if err != nil || h.Protocol != p.proto {
// 				fmt.Printf("not ours proto: %d\n", h.Protocol)
// 				continue
// 			}
// 			dst = h.Dst
// 			innerBody = data[h.Len:]
// 		case ipv6.ICMPTypeDestinationUnreachable.Protocol():
// 			h, err := ipv6.ParseHeader(data)
// 			if err != nil || h.NextHeader != p.proto {
// 				continue
// 			}
// 			dst = h.Dst
// 			innerBody = data[ipv6.HeaderLen:]
// 		}
// 		innerMsg, err := icmp.ParseMessage(p.proto, innerBody)
// 		if err != nil {
// 			fmt.Printf("unable to parse inner msg: %s\n", err)
// 			continue
// 		}
// 		innerEcho, ok := innerMsg.Body.(*icmp.Echo)
// 		if !ok {
// 			fmt.Printf("inner msg is not echo: %#v\n", innerMsg.Body)
// 			continue
// 		}
// 		return innerEcho, &net.IPAddr{IP: dst}, perr
// 	}
// }

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

func flatten(bb [][]byte, to []byte, n int) (ok bool) {
	// TODO
	if len(to) < n {
		return false
	}
	var r int
	for _, b := range bb {
		if len(b) > n-r {
			b = b[:n]
		}
		copy(to[r:], b)
		n -= len(b)
		r += len(b)
		if n <= 0 {
			return true
		}
	}
	return false
}
