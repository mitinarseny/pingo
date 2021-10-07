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

func newConn(family, proto int, laddr *net.UDPAddr, dst net.IP) (conn net.PacketConn, err error) {
	s, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
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

// send sends buffer to given destination with given options
func (p *Pinger) send(b []byte, dst net.IP, opts ...SetOption) (err error) {
	dstAddr := net.UDPAddr{IP: dst}
	oob := marshalOpts(opts...)
	switch p.proto {
	case unix.IPPROTO_ICMP:
		_, err = p.c4.WriteBatch([]ipv4.Message{{
			Buffers: [][]byte{b},
			OOB:     oob,
			Addr:    &dstAddr,
		}}, 0)
	case unix.IPPROTO_ICMPV6:
		_, err = p.c6.WriteBatch([]ipv6.Message{{
			Buffers: [][]byte{b},
			OOB:     oob,
			Addr:    &dstAddr,
		}}, 0)
	}
	return err
}

const (
	sizeOfICMPHeader     = 4                    // type, code and checksum
	sizeOfICMPEchoHeader = sizeOfICMPHeader + 4 // ID and seq are both uint16
	a                    = unsafe.Sizeof(unix.Timespec{})
)

var oobSize = unix.CmsgSpace(int(unsafe.Sizeof(unix.Timespec{}))) + // SO_TIMESTAMPNS_NEW
	// IP(V6)_RECVERR
	unix.CmsgSpace(int(
		unsafe.Sizeof(unix.SockExtendedErr{})+
			unsafe.Sizeof(unix.RawSockaddrAny{}))) +
	unix.CmsgSpace(int(unsafe.Sizeof(int32(0)))) // IP_RECVTTL / IPV6_RECVHOPLIMIT

// Listen handles receiving of incomming replies and routes them into calling
// Pinger.Ping* method, so *no* Pinger.Ping*() methods should be called before
// Listen and after it returns.
//
// msgBuffSize is a size of buffer for socket messages for receiving incoming packets.
// maxPayloadSize is a maximum size of ICMP payload to receive.
//
// NOTE: It is a blocking call, so it should be run as a separate goroutine.
// It returns a non-nil error if context is done or an error occured
// while receiving on sokcet.
func (p *Pinger) Listen(ctx context.Context, msgBuffSize, maxPayloadSize int) error {
	if msgBuffSize == 0 {
		panic("zero buffer size")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// unlock for reading
	if err := p.c.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		// lock for reading and make all pending reads return an error
		_ = p.c.SetReadDeadline(time.Now())
	}()

	ch := make(chan sockMsg, 100)
	defer close(ch)

	go p.dispatcher(ch)

	buffSize := sizeOfICMPEchoHeader + int(maxPayloadSize)
	var err error
	switch p.proto {
	case unix.IPPROTO_ICMP:
		err = p.read4(ch, msgBuffSize, buffSize)
	case unix.IPPROTO_ICMPV6:
		err = p.read6(ch, msgBuffSize, buffSize)
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		err = ctx.Err()
	}
	return err
}

type sockMsg struct {
	addr       net.Addr
	buff, oob  []byte
	receivedAt time.Time
}

func (p *Pinger) read4(ch chan<- sockMsg, msgBuffSize, buffSize int) error {
	ms := make([]ipv4.Message, msgBuffSize)
	for i := range ms {
		// make only one buffer since we either way will parse ICMP
		ms[i].Buffers = [][]byte{make([]byte, buffSize)}
		// TODO: sum of sizes of all controll messages
		ms[i].OOB = make([]byte, oobSize)
	}
	for {
		n, err := p.c4.ReadBatch(ms, 0)
		if errors.Is(err, unix.EHOSTUNREACH) {
			// there should be at least one ICMP error
			n, err = p.c4.ReadBatch(ms, unix.MSG_ERRQUEUE|unix.MSG_WAITFORONE)
		}
		if err != nil {
			return err
		}
		receivedAt := time.Now()
		for _, m := range ms[:n] {
			ch <- sockMsg{
				addr:       m.Addr,
				buff:       m.Buffers[0][:m.N],
				oob:        m.OOB[:m.NN],
				receivedAt: receivedAt,
			}
		}
	}
}

func (p *Pinger) read6(ch chan<- sockMsg, msgBuffSize, buffSize int) error {
	ms := make([]ipv6.Message, msgBuffSize)
	for i := range ms {
		// make only one buffer since we either way will parse ICMP
		ms[i].Buffers = [][]byte{make([]byte, buffSize)}
		// TODO: sum of sizes of all possible control messages
		ms[i].OOB = make([]byte, oobSize)
	}
	for {
		n, err := p.c6.ReadBatch(ms, 0)
		if errors.Is(err, unix.EHOSTUNREACH) {
			// there should be at least one ICMP error
			n, err = p.c6.ReadBatch(ms, unix.MSG_ERRQUEUE|unix.MSG_WAITFORONE)
		}
		if err != nil {
			return err
		}
		receivedAt := time.Now()
		for _, m := range ms[:n] {
			ch <- sockMsg{
				addr:       m.Addr,
				buff:       m.Buffers[0][:m.N],
				oob:        m.OOB[:m.NN],
				receivedAt: receivedAt,
			}
		}
	}
}

func (p *Pinger) dispatcher(ch <-chan sockMsg) {
	for msg := range ch {
		p.dispatch(msg.receivedAt, msg.addr, msg.buff, msg.oob)
	}
}

func (p *Pinger) dispatch(receivedAt time.Time, srcAddr net.Addr, buff, oob []byte) {
	src, ok := srcAddr.(*net.UDPAddr)
	if !ok {
		return
	}
	msg, err := icmp.ParseMessage(p.proto, buff)
	if err != nil {
		return
	}
	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		return
	}
	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return
	}
	var (
		icmpErr error
		ttl     uint8
	)
	for _, scm := range scms {
		switch scm.Header.Level {
		case unix.SOL_IP, unix.SOL_IPV6:
			switch scm.Header.Type {
			case unix.IP_RECVERR, unix.IPV6_RECVERR:
				se := (*unix.SockExtendedErr)(unsafe.Pointer(&scm.Data[0]))
				if se.Errno != uint32(unix.EHOSTUNREACH) {
					continue
				}
				switch se.Origin {
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
			case unix.IP_TTL, unix.IPV6_HOPLIMIT:
				ttl = uint8(*(*int32)(unsafe.Pointer(&scm.Data[0])))
			default:
				continue
			}

		case unix.SOL_SOCKET:
			if scm.Header.Type != unix.SO_TIMESTAMPNS_NEW {
				continue
			}
			receivedAt = time.Unix((*unix.Timespec)(unsafe.Pointer(&scm.Data[0])).Unix())
		default:
			continue
		}
	}
	p.dispatchEcho(receivedAt, src.IP, echo, ttl, icmpErr)
}

func (p *Pinger) dispatchTxTsEcho(echo *icmp.Echo, sentAt time.Time) {
	p.dispatchTxTsSeq(uint16(echo.Seq), sentAt)
}

func (p *Pinger) dispatchTxTsSeq(seq uint16, sentAt time.Time) {
	pend := p.seqs.get(seq)
	if pend == nil {
		return
	}
	pend.sentAt = sentAt
}

func (p *Pinger) dispatchEcho(receivedAt time.Time, dst net.IP, echo *icmp.Echo,
	ttl uint8, icmpErr error) {
	p.dispatchSeq(receivedAt, dst, uint16(echo.Seq), echo.Data, ttl, icmpErr)
}

func (p *Pinger) dispatchSeq(receivedAt time.Time, dst net.IP, seq uint16,
	payload []byte, ttl uint8, icmpErr error) {
	pend := p.seqs.pop(seq)
	if pend == nil || !dst.Equal(pend.dst) {
		// Drop the reply in following cases:
		//   * we did not send the echo request, which the reply came to
		//   * sender gave up waiting for the reply
		//   * the echo reply came from the address, which is different from
		//     the destination address, which the request was sent to
		return
	}

	select {
	case <-pend.ctx.Done():
		// sender gave up waiting for the reply
		return
	case pend.reply <- Reply{
		RTT:  receivedAt.Sub(pend.sentAt),
		TTL:  ttl,
		Data: payload,
		Err:  icmpErr,
	}:
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
