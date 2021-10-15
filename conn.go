package ping

import (
	"context"
	"errors"
	"fmt"
	"sync"
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
func newConn(family, proto int, laddr *net.UDPAddr, dst net.IP) (conn net.PacketConn, err error) {
	s, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, proto)
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

// sendSeq sends an ICMP Echo Request with given sequence number to given destination.
// opts can be used to ste per-packet sendmsg(2) options.
func (p *Pinger) sendSeq(seq uint16, dst net.IP, payload []byte, opts ...WOption) error {
	var typ icmp.Type
	switch p.proto {
	case unix.IPPROTO_ICMP:
		typ = ipv4.ICMPTypeEcho
	case unix.IPPROTO_ICMPV6:
		typ = ipv6.ICMPTypeEchoRequest
	}
	b, err := (&icmp.Message{
		Type: typ,
		Body: &icmp.Echo{
			// ID is chosen by kernel
			Seq:  int(seq),
			Data: payload,
		},
	}).Marshal(nil)
	if err != nil {
		return fmt.Errorf("marshal ICMP: %w", err)
	}

	oob := marshalOpts(opts...)
	var sa unix.Sockaddr
	if ip := dst.To4(); ip != nil {
		var sa4 unix.SockaddrInet4
		copy(sa4.Addr[:], ip)
		sa = &sa4
	} else if ip := ip.To16(); ip != nil {
		var sa6 unix.SockaddrInet6
		copy(sa6.Addr[:], ip.To16())
		sa = &sa6
	}
	var operr error
	if err := p.rc.Write(func(s uintptr) (done bool) {
		operr = unix.Sendmsg(int(s), b, oob, sa, 0)
		if operr == nil {
			// syscall.RawConn.Write locks for writing, so we are sure
			p.optIDs.now(seq)
		}
		return !errIsWouldBlockOr(operr)
	}); err != nil {
		return err
	}
	return os.NewSyscallError("sendmsg", operr)
}

const (
	sizeOfICMPHeader     = 4                    // type, code and checksum
	sizeOfICMPEchoHeader = sizeOfICMPHeader + 4 // ID and seq are both uint16
)

// rLock locks for reading and makes all pending requests return an error
func (p *Pinger) rLock() error {
	return p.c.SetReadDeadline(time.Now())
}

// rUnlock unlocks for readling
func (p *Pinger) rUnlock() error {
	return p.c.SetReadDeadline(time.Time{})
}

type sockMsg struct {
	buff, oob []byte
}

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
func (p *Pinger) Listen(ctx context.Context, maxPayloadSize int) error {
	if err := p.rUnlock(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	var g sync.WaitGroup
	defer g.Wait()
	g.Add(1)
	go func() {
		defer g.Done()

		<-ctx.Done()
		_ = p.rLock()
	}()
	defer cancel()

	// TODO: buff size
	ch := make(chan sockMsg, 100)
	defer close(ch)

	go p.dispatcher(ch)

	err := p.read(ch)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		err = ctx.Err()
	}
	return err
}

func (p *Pinger) read(ch chan<- sockMsg) error {
	// TODO: size
	const size = 1000
	buff := make([]byte, size)
	errQueueBuff := make([]byte, size)
	oob := make([]byte,
		unix.CmsgSpace(int(unsafe.Sizeof(unix.ScmTimestamping{})))+
			unix.CmsgSpace(int(TTL(0).Len())))
	errQueueOOB := make([]byte,
		unix.CmsgSpace(int(unsafe.Sizeof(unix.ScmTimestamping{})))+
			unix.CmsgSpace(int(
				unsafe.Sizeof(unix.SockExtendedErr{})+
					unsafe.Sizeof(unix.RawSockaddrInet6{})))+
			unix.CmsgSpace(int(TTL(0).Len())))

	send := func(b, oob []byte) {
		bb := make([]byte, len(b))
		copy(bb, b)
		oobb := make([]byte, len(oob))
		copy(oobb, oob)
		ch <- sockMsg{
			buff: bb,
			oob:  oobb,
		}
	}

	var (
		n, oobn, errQueueN, errQueueOOBN int
		operr, errQueueOperr             error
	)
	for {
		if err := p.rc.Read(func(s uintptr) (done bool) {
			n, oobn, _, _, operr = unix.Recvmsg(int(s), buff, oob, unix.MSG_DONTWAIT)
			errQueueN, errQueueOOBN, _, _, errQueueOperr = unix.Recvmsg(
				int(s), errQueueBuff, errQueueOOB, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
			return !(errIsWouldBlockOr(operr) && errIsWouldBlockOr(errQueueOperr))
		}); err != nil {
			return err
		}
		if errQueueOperr == nil {
			send(errQueueBuff[:errQueueN], errQueueOOB[:errQueueOOBN])
		} else if !errIsWouldBlockOr(errQueueOperr) {
			return os.NewSyscallError("recvmsg", errQueueOperr)
		}

		if operr == nil {
			send(buff[:n], oob[:oobn])
		} else if !errIsWouldBlockOr(operr, unix.EHOSTUNREACH) {
			return os.NewSyscallError("recvmsg", operr)
		}
	}
}

func (p *Pinger) dispatcher(ch <-chan sockMsg) {
	for msg := range ch {
		p.dispatch(msg.buff, msg.oob)
	}
}
func (p *Pinger) dispatch(buff, oob []byte) {
	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return
	}
	var (
		icmpErr       error
		ttl           uint8
		ts            time.Time
		isTxTimestamp bool
		optID         uint32
	)
	for _, scm := range scms {
		switch scm.Header.Level {
		case unix.SOL_IP, unix.SOL_IPV6:
			switch scm.Header.Type {
			case unix.IP_RECVERR, unix.IPV6_RECVERR:
				se := (*unix.SockExtendedErr)(unsafe.Pointer(&scm.Data[0]))
				switch se.Origin {
				case unix.SO_EE_ORIGIN_TIMESTAMPING:
					if unix.Errno(se.Errno) != unix.ENOMSG ||
						se.Info != unix.SCM_TSTAMP_SCHED {
						continue
					}
					isTxTimestamp = true
					optID = se.Data
					// TODO:
				case unix.SO_EE_ORIGIN_ICMP:
					if unix.Errno(se.Errno) != unix.EHOSTUNREACH {
						continue
					}
					sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(&scm.Data[unsafe.Sizeof(*se)]))
					switch se.Type {
					case uint8(ipv4.ICMPTypeDestinationUnreachable):
						icmpErr = NewDestinationUnreachableError(sa.Addr[:],
							DstUnreachableCode(se.Code))
					case uint8(ipv4.ICMPTypeTimeExceeded):
						icmpErr = NewTimeExceededError(sa.Addr[:])
					}
				case unix.SO_EE_ORIGIN_ICMP6:
					if unix.Errno(se.Errno) != unix.EHOSTUNREACH {
						continue
					}
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
				ttlOpt := TTL(0)
				ttlOpt.Unmarshal(scm.Data)
				ttl = ttlOpt.Get()
			}
		case unix.SOL_SOCKET:
			switch scm.Header.Type {
			case unix.SCM_TIMESTAMPING:
				ts = time.Unix((*unix.ScmTimestamping)(unsafe.Pointer(&scm.Data[0])).Ts[0].Unix())
			}
		}
	}
	if isTxTimestamp {
		p.dispatchTxTsSeq(p.optIDs.pop(optID), ts)
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
	p.dispatchSeq(uint16(echo.Seq), ts, echo.Data, ttl, icmpErr)
}

func (p *Pinger) dispatchTxTsSeq(seq uint16, sentAt time.Time) {
	pend := p.seqs.get(seq)
	if pend == nil {
		return
	}
	pend.sentAt = sentAt
}

func (p *Pinger) dispatchSeq(seq uint16, receivedAt time.Time,
	payload []byte, ttl uint8, icmpErr error) {
	pend := p.seqs.get(seq)
	if pend == nil {
		// Drop the reply in following cases:
		//   * we did not send the echo request, which the reply came to
		//   * sender gave up waiting for the reply
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

func errIsWouldBlockOr(err error, errs ...error) bool {
	return errIsOneOf(err, append(errs, unix.EAGAIN, unix.EWOULDBLOCK)...)
}

func errIsOneOf(err error, errs ...error) bool {
	for _, e := range errs {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}
