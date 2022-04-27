package ping

import (
	"net"
	"unsafe"

	unixx "github.com/mitinarseny/pingo/unix"
	"golang.org/x/sys/unix"
)

// MTU is <SOL_IP, IP_MTU>
func MTU(mtu int32) unixx.Int32SockOpt {
	return unixx.NewInt32SockOpt(unix.SOL_IP, unix.IP_MTU).Set(mtu)
}

// MTU6 is <SOL_IPV6, IPV6_MTU>
func MTU6(mtu int32) unixx.Int32SockOpt {
	return unixx.NewInt32SockOpt(unix.SOL_IPV6, unix.IPV6_MTU).Set(mtu)
}

// TTL is <SOL_IP, IP_TTL>
func TTL(ttl uint8) unixx.Uint8SockOpt {
	return unixx.NewUint8SockOpt(unix.SOL_IP, unix.IP_TTL).Set(ttl)
}

// TTL is <SOL_IPV6, IPV6_HOPLIMIT>
func HopLimit(hl uint8) unixx.Uint8SockOpt {
	return unixx.NewUint8SockOpt(unix.SOL_IPV6, unix.IPV6_HOPLIMIT).Set(hl)
}

var _ = unixx.RWSockOpt(&PktInfo{})

// PktInfo is <SOL_IP, IP_PKTINFO>
type PktInfo struct {
	Src, Dst net.IP
	IfIndex  int32
}

func (o *PktInfo) Level() int32 {
	return unix.SOL_IP
}

func (o *PktInfo) Type() int32 {
	return unix.IP_PKTINFO
}

func (o *PktInfo) Len() uint64 {
	return unix.SizeofInet4Pktinfo
}

func (o *PktInfo) Marshal(b []byte) {
	pi := (*unix.Inet4Pktinfo)(unsafe.Pointer(&b[0]))
	if ip := o.Src.To4(); ip != nil {
		copy(pi.Spec_dst[:], ip)
	}
	if o.IfIndex > 0 {
		pi.Ifindex = o.IfIndex
	}
}

func (o *PktInfo) Unmarshal(b []byte) {
	pi := (*unix.Inet4Pktinfo)(unsafe.Pointer(&b[0]))
	o.IfIndex = pi.Ifindex
	if len(o.Dst) < net.IPv4len {
		o.Dst = make(net.IP, net.IPv4len)
	}
	copy(o.Dst, pi.Addr[:])
}

var _ = unixx.RWSockOpt(&PktInfo6{})

// PktInfo is <SOL_IPV6, IPV6_PKTINFO>
type PktInfo6 struct {
	Src, Dst net.IP
	IfIndex  uint32
}

func (o *PktInfo6) Level() int32 {
	return unix.SOL_IPV6
}

func (o *PktInfo6) Type() int32 {
	return unix.IPV6_PKTINFO
}

func (o *PktInfo6) Len() uint64 {
	return unix.SizeofInet6Pktinfo
}

func (o *PktInfo6) Marshal(b []byte) {
	pi := (*unix.Inet6Pktinfo)(unsafe.Pointer(&b[0]))
	if ip := o.Src.To16(); ip != nil && ip.To4() == nil {
		copy(pi.Addr[:], ip)
	}
	if o.IfIndex > 0 {
		pi.Ifindex = o.IfIndex
	}
}

func (o *PktInfo6) Unmarshal(b []byte) {
	pi := (*unix.Inet6Pktinfo)(unsafe.Pointer(&b[0]))
	o.IfIndex = pi.Ifindex
	if len(o.Dst) < net.IPv6len {
		o.Dst = make(net.IP, net.IPv6len)
	}
	copy(o.Dst, pi.Addr[:])
}

// TrafficClass is <SOL_IPV6, IPV6_TCLASS>
func TrafficClass(tc uint8) unixx.Uint8SockOpt {
	return unixx.NewUint8SockOpt(unix.SOL_IPV6, unix.IPV6_TCLASS).Set(tc)
}

var _ = unixx.RWSockOpt(&PathMTU{})

// PathMTU is <SOL_IPV6, IPV6_PATHMTU>
type PathMTU struct {
	MTU     uint32
	Dst     net.IP
	IfIndex uint32
}

func (o *PathMTU) Level() int32 {
	return unix.SOL_IPV6
}

func (o *PathMTU) Type() int32 {
	return unix.IPV6_PATHMTU
}

func (o *PathMTU) Len() uint64 {
	return unix.SizeofIPv6MTUInfo
}

func (o *PathMTU) Marshal(b []byte) {
	(*unix.IPv6MTUInfo)(unsafe.Pointer(&b[0])).Mtu = uint32(o.MTU)
}

func (o *PathMTU) Unmarshal(b []byte) {
	mi := (*unix.IPv6MTUInfo)(unsafe.Pointer(&b[0]))
	if len(o.Dst) < net.IPv6len {
		o.Dst = make(net.IP, net.IPv6len)
	}
	copy(o.Dst, mi.Addr.Addr[:])
	o.IfIndex = mi.Addr.Scope_id
	o.MTU = mi.Mtu
}

// recvErr is <SOL_IP, IP_RECVERR>
func recvErr(v bool) unixx.BoolSockOpt {
	return unixx.NewBoolSockOpt(unix.SOL_IP, unix.IP_RECVERR).Set(v)
}

// recvErr6 is <SOL_IPV6, IPV6_RECVERR>
func recvErr6(v bool) unixx.BoolSockOpt {
	return unixx.NewBoolSockOpt(unix.SOL_IPV6, unix.IPV6_RECVERR).Set(v)
}

// recvTTL is <SOL_IP, IP_RECVTTL>
func recvTTL(v bool) unixx.BoolSockOpt {
	return unixx.NewBoolSockOpt(unix.SOL_IP, unix.IP_RECVTTL).Set(v)
}

// recvHopLimit is <SOL_IPV6, IPV6_RECVHOPLIMIT>
func recvHopLimit(v bool) unixx.BoolSockOpt {
	return unixx.NewBoolSockOpt(unix.SOL_IPV6, unix.IPV6_RECVHOPLIMIT).Set(v)
}
