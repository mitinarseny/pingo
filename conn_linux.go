package ping

import (
	"net"
	"os"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func newConn(laddr, dst net.IP) (conn *net.UDPConn, proto int, err error) {
	if laddr == nil {
		laddr = net.IPv4zero
	}
	var family int
	if laddr.To4() != nil {
		family, proto = syscall.AF_INET, ipv4.ICMPTypeEcho.Protocol()
	} else {
		family, proto = syscall.AF_INET6, ipv6.ICMPTypeEchoRequest.Protocol()
	}
	s, err := syscall.Socket(family, syscall.SOCK_DGRAM, proto)
	if err != nil {
		return nil, 0, os.NewSyscallError("socket", err)
	}
	if err := syscall.Bind(s, sockaddr(laddr)); err != nil {
		syscall.Close(s)
		return nil, 0, os.NewSyscallError("bind", err)
	}
	if dst != nil {
		if err := syscall.Connect(s, sockaddr(dst)); err != nil {
			syscall.Close(s)
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

func sockaddr(ip net.IP) syscall.Sockaddr {
	if ip.To4() != nil {
		ip = ip.To4()
		var sa syscall.SockaddrInet4
		copy(sa.Addr[:], ip)
		return &sa
	}
	var sa syscall.SockaddrInet6
	copy(sa.Addr[:], ip)
	return &sa
}
