package ping

import (
	"net"
	"os"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
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
		if err := syscall.Connect(s, sockaddr(&net.UDPAddr{IP: dst})); err != nil {
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

// sockaddr converts *net.UDPAddr to syscall.Sockaddr
func sockaddr(addr *net.UDPAddr) syscall.Sockaddr {
	if ip4 := addr.IP.To4(); ip4 != nil {
		sa := syscall.SockaddrInet4{
			Port: addr.Port,
		}
		copy(sa.Addr[:], ip4)
		return &sa
	}
	sa := syscall.SockaddrInet6{
		Port: addr.Port,
	}
	copy(sa.Addr[:], addr.IP.To16())
	return &sa
}
