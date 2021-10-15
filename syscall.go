package ping

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func (p *Pinger) sendmsg(b, oob []byte, dst net.IP, flags int) error {
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
		operr = unix.Sendmsg(int(s), b, oob, sa, flags)
		return ioComplete(flags, operr)
	}); err != nil {
		return err
	}
	fmt.Printf("sendmsg buff: %v\n", b)
	return operr
}

func recvmsgUDP(s int, b, oob []byte, flags int) (n, oobn int, recvflags int, from *net.UDPAddr, err error) {
	var sa unix.Sockaddr
	n, oobn, recvflags, sa, err = unix.Recvmsg(s, b, oob, flags)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		from = &net.UDPAddr{IP: sa.Addr[:], Port: sa.Port}
	case *unix.SockaddrInet6:
		from = &net.UDPAddr{IP: sa.Addr[:], Port: sa.Port}
	}
	return n, oobn, recvflags, from, nil
}

// TODO: rm
func (p *Pinger) recvmsg(b, oob []byte, flags int) (n, oobn int, recvflags int, from net.Addr, err error) {
	var (
		operr error
		sa    unix.Sockaddr
	)
	if err := p.rc.Read(func(s uintptr) (done bool) {
		n, oobn, recvflags, sa, operr = unix.Recvmsg(int(s), b, oob, flags)
		return ioComplete(flags, operr)
	}); err != nil {
		return 0, 0, 0, nil, err
	}
	if operr != nil {
		return 0, 0, 0, nil, operr
	}
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		from = &net.UDPAddr{IP: sa.Addr[:], Port: sa.Port}
	case *unix.SockaddrInet6:
		from = &net.UDPAddr{IP: sa.Addr[:], Port: sa.Port}
	}
	return n, oobn, recvflags, from, nil
}

func ioComplete(flags int, operr error) bool {
	return flags&unix.MSG_DONTWAIT != 0 ||
		(operr != unix.EAGAIN && operr != unix.EWOULDBLOCK)
}
