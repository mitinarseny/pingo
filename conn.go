package ping

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"net"
	"os"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

// newConn returns a new udp connection with given local and destination addresses.
// laddr should be a valid IP address, while dst could be nil.
// Non-nil dst means that ICMP packets could be sent to and received from
// only given address, pinging different address would result in error.
// The returner proto is ICMP protocol number.

func newConn(family, proto int, laddr *net.UDPAddr, dst net.IP) (net.PacketConn, error) {
	s, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	if err := unix.SetsockoptInt(s, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
		unix.Close(s)
		return nil, os.NewSyscallError("setsockopt", err)
	}
	// TODO: this may be not supported
	if err := unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1); err != nil {
		unix.Close(s)
		return nil, os.NewSyscallError("setsockopt", err)
	}
	// TODO: unix.SOF_TIMESTAMPING_OPT_TSONLY
	if err := unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_TIMESTAMPING,
		unix.SOF_TIMESTAMPING_RX_SOFTWARE|unix.SOF_TIMESTAMPING_TX_SOFTWARE|
			unix.SOF_TIMESTAMPING_OPT_CMSG|unix.SOF_TIMESTAMPING_OPT_ID|
			unix.SOF_TIMESTAMPING_TX_SCHED|unix.SOF_TIMESTAMPING_SOFTWARE); err != nil {
		unix.Close(s)
		return nil, os.NewSyscallError("setsockopt", err)
	}
	if err := unix.Bind(s, sockaddr(laddr)); err != nil {
		unix.Close(s)
		return nil, os.NewSyscallError("bind", err)
	}
	if dst != nil {
		if err := unix.Connect(s, sockaddr(&net.UDPAddr{IP: dst})); err != nil {
			unix.Close(s)
			return nil, os.NewSyscallError("connect", err)
		}
	}
	f := os.NewFile(uintptr(s), "datagram-oriented icmp")
	c, err := net.FilePacketConn(f)
	if cerr := f.Close(); cerr != nil {
		return nil, cerr
	}
	return c, err
}

// TTL returns current TTL set for outgoing packages
func (p *Pinger) TTL() (uint8, error) {
	var (
		ttl int
		err error
	)
	switch p.proto {
	case unix.IPPROTO_ICMP:
		ttl, err = p.c4.TTL()
	case unix.IPPROTO_ICMPV6:
		ttl, err = p.c6.HopLimit()
	}
	return uint8(ttl), err
}

// SetTTL with non-zero sets the given Time-to-Live on all outgoing IP packets.
// Pass ttl 0 to get the current value.
func (p *Pinger) SetTTL(ttl uint8) error {
	if p.proto == unix.IPPROTO_ICMP {
		return p.c4.SetTTL(int(ttl))
	}
	return p.c6.SetHopLimit(int(ttl))
}

// send sends buffer to given destination
func (p *Pinger) send(b []byte, dst net.IP) (err error) {
	dstAddr := net.UDPAddr{IP: dst}
	switch p.proto {
	case unix.IPPROTO_ICMP:
		_, err = p.c4.WriteTo(b, nil, &dstAddr)
	case unix.IPPROTO_ICMPV6:
		_, err = p.c6.WriteTo(b, nil, &dstAddr)
	}
	return err
}

func (p *Pinger) read4ErrQueue(ch chan<- socketMessage) error {
	ms := make([]ipv4.Message, 10)
	for i := range ms {
		ms[i].Buffers = [][]byte{make([]byte, 1500)}
		ms[i].OOB = make([]byte, 1500)
	}
	for {
		fmt.Println("read errq")
		n, err := p.c4.ReadBatch(ms, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
		fmt.Printf("read errq err: %s", err)
		if err != nil {
			return err
		}
		for _, m := range ms[:n] {
			ch <- socketMessage{
				addr: m.Addr,
				buff: m.Buffers[0][:m.N],
				oob:  m.OOB[:m.NN],
			}
		}
	}
}

func (p *Pinger) read4(ch chan<- socketMessage, msgBuffSize, buffSize int) error {
	var g errgroup.Group
	// g.Go(func() error {
	// 	return p.read4N(ch, msgBuffSize, buffSize)
	// })
	g.Go(func() error {
		return p.read4ErrQueue(ch)
	})
	return g.Wait()
}

func (p *Pinger) read4N(ch chan<- socketMessage, msgBuffSize, buffSize int) error {
	ms := make([]ipv4.Message, msgBuffSize)
	for i := range ms {
		// make only one buffer since we either way will parse ICMP
		ms[i].Buffers = [][]byte{make([]byte, buffSize)}
		// TODO: sum of sizes of all controll messages
		ms[i].OOB = make([]byte, 1500)
	}
	for {
		n, err := p.c4.ReadBatch(ms, 0)
		// TODO ENOMSG?
		fmt.Printf("readbatch err: %s\n", err)
		if errors.Is(err, unix.EHOSTUNREACH) {
			// there should be at least one ICMP error
			n, err = p.c4.ReadBatch(ms, unix.MSG_ERRQUEUE|unix.MSG_WAITFORONE)
		}
		if err != nil {
			return err
		}
		for _, m := range ms[:n] {
			ch <- socketMessage{
				addr: m.Addr,
				buff: m.Buffers[0][:m.N],
				oob:  m.OOB[:m.NN],
			}
		}
	}
}

func (p *Pinger) read6(ch chan<- socketMessage, msgBuffSize, buffSize int) error {
	ms := make([]ipv6.Message, msgBuffSize)
	for i := range ms {
		// make only one buffer since we either way will parse ICMP
		ms[i].Buffers = [][]byte{make([]byte, buffSize)}
		// TODO: sum of sizes of all possible control messages
		ms[i].OOB = make([]byte, 1500)
	}
	for {
		n, err := p.c6.ReadBatch(ms, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EHOSTUNREACH) {
			// there should be at least one ICMP error
			n, err = p.c6.ReadBatch(ms, unix.MSG_ERRQUEUE|unix.MSG_WAITFORONE)
		}
		if err != nil {
			return err
		}
		for _, m := range ms[:n] {
			ch <- socketMessage{
				addr: m.Addr,
				buff: m.Buffers[0][:m.N],
				oob:  m.OOB[:m.NN],
			}
		}
	}
}

type socketMessage struct {
	addr      net.Addr
	buff, oob []byte
}

type tsts struct {
	sentAt time.Time
	seq    uint16
}

func (p *Pinger) txTsDispatcher(ch <-chan tsts) {
	for t := range ch {
		p.dispatchSendTs(t.seq, t.sentAt)
	}
}

func (p *Pinger) dispatcher(ch <-chan socketMessage) {
	for msg := range ch {
		p.dispatch(msg.addr, msg.buff, msg.oob)
	}
}

func (p *Pinger) dispatch(srcAddr net.Addr, buff, oob []byte) {
	src, ok := srcAddr.(*net.UDPAddr)
	if !ok {
		fmt.Printf("src addr is not udp\n")
		return
	}
	msg, err := icmp.ParseMessage(p.proto, buff)
	if err != nil {
		fmt.Printf("unable to parse icmp: %s\n", err)
		return
	}
	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		fmt.Println("msg body is not echo")
		return
	}
	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		fmt.Printf("unable to parse scm: %s\n", err)
		return
	}
	var (
		icmpErr error
		ts      time.Time
	)
	// fmt.Printf("scms: %#v\n", scms)
	for i, scm := range scms {
		fmt.Printf("msg #%d: level: 0x%x, type: 0x%x\n", i, scm.Header.Level, scm.Header.Type)
		switch scm.Header.Level {
		case unix.IPPROTO_IP, unix.IPPROTO_IPV6:
			if (scm.Header.Level == unix.IPPROTO_IP &&
				scm.Header.Type != unix.IP_RECVERR) ||
				(scm.Header.Level == unix.IPPROTO_IPV6 &&
					scm.Header.Type != unix.IPV6_RECVERR) {
				continue
			}
			se := (*unix.SockExtendedErr)(unsafe.Pointer(&scm.Data[0]))
			switch se.Errno {
			case uint32(unix.EHOSTUNREACH):
				switch se.Origin {
				// TODO: unix.SO_EE_ORIGIN_LOCAL
				case unix.SO_EE_ORIGIN_ICMP:
					sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(&scm.Data[unsafe.Sizeof(*se)]))
					switch se.Type {
					case uint8(ipv4.ICMPTypeDestinationUnreachable):
						icmpErr = NewDestinationUnreachableError(sa.Addr[:],
							DstUnreachableCode(se.Code))
					case uint8(ipv4.ICMPTypeTimeExceeded):
						icmpErr = NewTimeExceededError(sa.Addr[:])
					}
				case unix.SO_EE_ORIGIN_ICMP6:
					sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(&scm.Data[unsafe.Sizeof(*se)]))
					switch se.Type {
					case uint8(ipv6.ICMPTypeDestinationUnreachable):
						icmpErr = NewDestinationUnreachableError(sa.Addr[:],
							DstUnreachableCode(se.Code))
					case uint8(ipv6.ICMPTypeTimeExceeded):
						icmpErr = NewTimeExceededError(sa.Addr[:])
					}
				}
			case uint32(unix.ENOMSG):
				fmt.Println("enomsg")
				if ts.IsZero() {
					for _, scm := range scms[i:] {
						if !(scm.Header.Level == unix.SOL_SOCKET &&
							scm.Header.Type == unix.SO_TIMESTAMPING) {
							continue
						}
						sts := (*unix.ScmTimestamping)(unsafe.Pointer(&scm.Data[0]))
						hwTS := sts.Ts[0]
						ts = time.Unix(hwTS.Unix())
					}
				}
				p.dispatchSendTs(uint16(echo.Seq), ts)
				return
			}
		case unix.SOL_SOCKET:
			if scm.Header.Type != unix.SO_TIMESTAMPNS {
				continue
			}
			fmt.Println("set SO_TIMESTAMPNS")
			sts := (*unix.ScmTimestamping)(unsafe.Pointer(&scm.Data[0]))
			hwTS := sts.Ts[0]
			ts = time.Unix(hwTS.Unix())
			// fmt.Printf("sts: %#v\n", sts)
		}
	}
	p.dispatchEcho(ts, src.IP, echo, icmpErr)
}

func (p *Pinger) dispatchSendTs(seq uint16, sentAt time.Time) {
	pend := p.seqs.get(seq)
	if pend == nil {
		return
	}
	fmt.Printf("recieved ts for seq %d\n", seq)
	select {
	case <-pend.ctx.Done():
	case pend.sentAt <- sentAt:
	}
	fmt.Printf("set ts for seq %d\n", seq)
}

func (p *Pinger) dispatchEcho(receivedAt time.Time, dst net.IP, echo *icmp.Echo, icmpErr error) {
	p.dispatchSeq(receivedAt, dst, uint16(echo.Seq), echo.Data, icmpErr)
}

func (p *Pinger) dispatchSeq(receivedAt time.Time, dst net.IP, seq uint16,
	payload []byte, icmpErr error) {
	pend := p.seqs.pop(seq)
	if pend == nil || !dst.Equal(pend.dst) {
		// Drop the reply in following cases:
		//   * we did not send the echo request, which the reply came to
		//   * sender gave up waiting for the reply
		//   * the echo reply came from the address, which is different from
		//     the destination address, which the request was sent to
		if pend == nil {
			fmt.Printf("pend nil for seq %d\n", seq)
		} else {
			fmt.Printf("pend dst not eq for seq %d: dst: %s, pend.dst: %s\n", seq, dst, pend.dst)
		}
		return
	}
	fmt.Printf("===================== send seq: %d\n", seq)

	var sentAt time.Time
	// select {
	// case <-pend.ctx.Done():
	// 	fmt.Printf("pend cont done for seq %d\n", seq)
	// 	return
	// case sentAt = <-pend.sentAt:
	// 	fmt.Printf("pend seq %d sentAt got\n", seq)
	// }
	select {
	case <-pend.ctx.Done():
		fmt.Printf("pend cont done for seq %d\n", seq)
		// sender gave up waiting for the reply
	// TODO: do not send anything is context is done
	// TODO: and close the reply chan
	case pend.reply <- Reply{
		RTT:  receivedAt.Sub(sentAt),
		Data: payload,
		Err:  icmpErr,
	}:
		fmt.Printf("===================== sent seq: %d!\n", seq)
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
