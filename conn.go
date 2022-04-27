package ping

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	unixx "github.com/mitinarseny/pingo/unix"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// send sends ICMP message of given type and code with diven body to dst.
// opts can be used to ste per-packet sendmsg(2) options.
func (p *Pinger) send(typ icmp.Type, code uint8, body icmp.MessageBody, dst net.IP, onSent func(), opts ...unixx.WSockOpt) error {
	b, err := (&icmp.Message{
		Type: typ,
		Code: int(code),
		Body: body,
	}).Marshal(nil)
	if err != nil {
		return fmt.Errorf("marshal ICMP message: %w", err)
	}

	oob := unixx.MarshalCmsg(opts...)
	sa := sockaddr(&net.UDPAddr{IP: dst})
	var operr error
	if err := p.c.Write(func(s uintptr) (done bool) {
		operr = unix.Sendmsg(int(s), b, oob, sa, 0)
		if operr == nil {
			// syscall.RawConn.Write locks for writing,
			// so everything here is called atomically.
			atomic.AddUint32(&p.currentOptID, 1)
			if onSent != nil {
				onSent()
			}
		}
		return !errIsWouldBlockOr(operr)
	}); err != nil {
		return err
	}
	return os.NewSyscallError("sendmsg", operr)
}

type sockMsg struct {
	buff, oob []byte
}

// read reads messgaes from underlying socket and its error queue
// and sends them to channel.
// numMsgs is the number of mmsghdrs to create.
func (p *Pinger) read(ch chan<- sockMsg, numMsgs int) error {
	const mtu = 1500

	oobSize := unix.CmsgSpace(int(unsafe.Sizeof(unix.ScmTimestamping{}))) +
		unix.CmsgSpace(int(TTL(0).Len()))
	namelen := unix.SizeofSockaddrInet4
	if p.IsIPv6() {
		namelen = unix.SizeofSockaddrInet6
	}
	names, buffs, oobs, hs := unixx.MakeMmsghdrs(numMsgs, namelen, mtu, oobSize)
	_, errQueueBuffs, errQueueOOBs, errQueueHs := unixx.MakeMmsghdrs(numMsgs, 0,
		mtu, oobSize+unix.CmsgSpace(
			int(unsafe.Sizeof(unix.SockExtendedErr{})+unix.SizeofSockaddrAny)))

	dispatchAndReset := func(hs []unixx.Mmsghdr, buffs [][]byte, oobs [][]byte) {
		for i := range hs {
			var from net.IP
			if hs[i].Hdr.Namelen == uint32(namelen) {
				var name []byte
				switch namelen {
				case unix.SizeofSockaddrInet4:
					name = (*unix.RawSockaddrInet4)(names[i]).Addr[:]
				case unix.SizeofSockaddrInet6:
					name = (*unix.RawSockaddrInet6)(names[i]).Addr[:]
				}
				from = make(net.IP, len(name))
				copy(from, name)
			}

			// copy buffers
			p.dispatch(from, append([]byte(nil), buffs[i][:hs[i].Len]...),
				append([]byte(nil), oobs[i][:hs[i].Hdr.Controllen]...))

			// we need to reset control length to original oob length
			// since it was changed by recvmmsg(2).
			hs[i].Hdr.Namelen = uint32(namelen)
			hs[i].Hdr.SetControllen(len(oobs[i]))
		}
	}

	var (
		n, errQueueN         int
		operr, errQueueOperr error
	)
	for {
		if err := p.c.Read(func(s uintptr) (done bool) {
			// Call recvmmsg for both socket and its error queue since
			// syscall.RawConn.Read() locks socket for reading.
			//
			// Raw syscalls recvmmsg(2) in conjuction with epoll_wait(2) without
			// syscall.RawConn wrapper wouldn't be the best choice since
			// syscall.RawConn uses internal/poll.FD, which internally uses
			// runtime_pollWait, which makes current thread available for others
			// goroutines while waiting for data to receive.
			// Golang restrics usage of internal/ packages, so it is the only way
			// to avoid locking current OS thread by this goroutine.
			n, operr = unixx.Recvmmsg(s, hs, unix.MSG_DONTWAIT)
			errQueueN, errQueueOperr = unixx.Recvmmsg(s, errQueueHs, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
			// we are done as soon as at least one of operrs does not
			// denote blocking operation.
			return !(errIsWouldBlockOr(operr) && errIsWouldBlockOr(errQueueOperr))
		}); err != nil {
			return err
		}

		// process data from the error queue first since it may contain transmit timestamps
		if errQueueOperr == nil {
			dispatchAndReset(errQueueHs[:errQueueN],
				errQueueBuffs[:errQueueN], errQueueOOBs[:errQueueN])
		} else if !errIsWouldBlockOr(errQueueOperr) {
			return os.NewSyscallError("recvmmsg", errQueueOperr)
		}

		if operr == nil {
			dispatchAndReset(hs[:n], buffs[:n], oobs[:n])
		} else if !errIsWouldBlockOr(operr, unix.EHOSTUNREACH) {
			return os.NewSyscallError("recvmmsg", operr)
		}
	}
}

// dispatch extracts
//   * ICMP reply or ICMP error from given recvmsg(2) buffer and
//     socket control messages and dispatches them to the sender
//   * transmit timestamp and updates corresponding pending request
func (p *Pinger) dispatch(from net.IP, buff, oob []byte) {
	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return
	}
	var (
		icmpErr       ICMPError
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
					optID = se.Data // unix.SOF_TIMESTAMPING_OPT_ID
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
			case unix.IP_TTL:
				ttlOpt := TTL(0)
				ttlOpt.Unmarshal(scm.Data)
				ttl = ttlOpt.Get()
			case unix.IPV6_HOPLIMIT:
				hlOpt := HopLimit(0)
				hlOpt.Unmarshal(scm.Data)
				ttl = hlOpt.Get()
			}
		case unix.SOL_SOCKET:
			switch scm.Header.Type {
			case unix.SCM_TIMESTAMPING:
				ts = time.Unix((*unix.ScmTimestamping)(unsafe.Pointer(&scm.Data[0])).Ts[0].Unix())
			}
		}
	}

	if isTxTimestamp {
		p.mu.Lock()
		if seq, found := p.optIDsToSeqs[optID]; found {
			p.seqs.sentAt(seq, ts)
			delete(p.optIDsToSeqs, optID)
		}
		p.mu.Unlock()
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
	p.seqs.reply(from, uint16(echo.Seq), ts, echo.Data, ttl, icmpErr)
}

// sockaddr converts *net.UDPAddr to syscall.Sockaddr
func sockaddr(addr *net.UDPAddr) unix.Sockaddr {
	if ip := addr.IP.To4(); ip != nil {
		sa := unix.SockaddrInet4{
			Port: addr.Port,
		}
		copy(sa.Addr[:], ip)
		return &sa
	} else if ip = addr.IP.To16(); ip != nil {
		sa := unix.SockaddrInet6{
			Port: addr.Port,
		}
		copy(sa.Addr[:], addr.IP.To16())
		return &sa
	}
	return nil
}

// errIsWouldBlockOr returns whether given error denotes blocking operation
// or is one of errs
func errIsWouldBlockOr(err error, errs ...error) bool {
	return errIsOneOf(err, append(errs, unix.EAGAIN, unix.EWOULDBLOCK)...)
}

// errIsOneOf returns whether given error is one of errs
func errIsOneOf(err error, errs ...error) bool {
	for _, e := range errs {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}
