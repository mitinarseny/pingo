package ping

import (
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type Option interface {
	Level() int32
	Type() int32
	Len() uint64
}

type SetOption interface {
	Option
	Marshal([]byte)
}

type GetOption interface {
	Option
	Unmarshal([]byte)
}

type GenericOption struct {
	Lvl   int32
	Typ   int32
	Value []byte
}

func (o *GenericOption) Level() int32 {
	return o.Lvl
}

func (o *GenericOption) Type() int32 {
	return o.Typ
}

func (o *GenericOption) Len() uint64 {
	return uint64(len(o.Value))
}

func (o *GenericOption) Marshal(b []byte) {
	copy(b, o.Value)
}

func (o *GenericOption) Unmarshal(b []byte) {
	copy(o.Value, b)
}

type GenericBoolOption struct {
	Lvl   int32
	Typ   int32
	Value bool
}

func (o *GenericBoolOption) Level() int32 {
	return o.Lvl
}

func (o *GenericBoolOption) Type() int32 {
	return o.Typ
}

func (o *GenericBoolOption) Len() uint64 {
	return uint64(unsafe.Sizeof(int32(0)))
}

func (o *GenericBoolOption) Marshal(b []byte) {
	marshalBoolAsInt32(b, o.Value)
}

func (o *GenericBoolOption) Unmarshal(b []byte) {
	o.Value = unmarshalBoolFromInt32(b)
}

// Set sets given options on the underlying socket with setsockopt(2)
func (p *Pinger) Set(opts ...SetOption) error {
	c, err := p.c.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}
	var operr error
	if err := c.Control(func(fd uintptr) {
		for _, o := range opts {
			b := make([]byte, o.Len())
			o.Marshal(b)
			if operr = unix.SetsockoptString(int(fd), int(o.Level()),
				int(o.Type()), string(b)); operr != nil {
				break
			}

		}
	}); err != nil {
		return err
	}
	return os.NewSyscallError("setsockopt", operr)
}

// Get gets given options from the underlying socket with getsockopt(2)
func (p *Pinger) Get(opts ...GetOption) error {
	c, err := p.c.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}
	var operr error
	if err := c.Control(func(fd uintptr) {
		for _, o := range opts {
			var s string
			s, operr = unix.GetsockoptString(int(fd), int(o.Level()), int(o.Type()))
			if operr != nil {
				break
			}
			o.Unmarshal([]byte(s))
		}
	}); err != nil {
		return err
	}
	return os.NewSyscallError("getsockopt", operr)
}

func marshalOpts(opts ...SetOption) []byte {
	if len(opts) == 0 {
		return nil
	}
	var l int
	for _, o := range opts {
		l += unix.CmsgSpace(int(o.Len()))
	}
	b := make([]byte, l)
	bb := b
	for _, o := range opts {
		h := (*unix.Cmsghdr)(unsafe.Pointer(&bb[0]))
		h.Level = o.Level()
		h.Type = o.Type()
		h.Len = uint64(unix.CmsgLen(int(o.Len())))
		o.Marshal(bb[unix.CmsgLen(0):h.Len])
		bb = bb[unix.CmsgSpace(int(o.Len())):]
	}
	return b
}

type TTL uint8

func (o TTL) Level() int32 {
	return unix.SOL_IP
}

func (o TTL) Type() int32 {
	return unix.IP_TTL
}

func (o TTL) Len() uint64 {
	return uint64(unsafe.Sizeof(uint32(o)))
}

func (o TTL) Marshal(b []byte) {
	*(*uint32)(unsafe.Pointer(&b[0])) = uint32(o)
}

func (o *TTL) Unmarshal(b []byte) {
	*o = TTL(*(*uint32)(unsafe.Pointer(&b[0])))
}

func marshalBoolAsInt32(b []byte, v bool) {
	*(*int32)(unsafe.Pointer(&b[0])) = b2i(v)
}

func unmarshalBoolFromInt32(b []byte) bool {
	return i2b(*(*int32)(unsafe.Pointer(&b[0])))
}

type recvTTL bool

func (o recvTTL) Level() int32 {
	return unix.SOL_IP
}

func (o recvTTL) Type() int32 {
	return unix.IP_RECVTTL
}

func (o recvTTL) Len() uint64 {
	return uint64(unsafe.Sizeof(int32(0)))
}

func (o recvTTL) Marshal(b []byte) {
	marshalBoolAsInt32(b, bool(o))
}

func (o *recvTTL) Unmarshal(b []byte) {
	*o = recvTTL(unmarshalBoolFromInt32(b))
}

type HopLimit uint8

func (o HopLimit) Level() int32 {
	return unix.SOL_IPV6
}

func (o HopLimit) Type() int32 {
	return unix.IPV6_HOPLIMIT
}

func (o HopLimit) Len() uint64 {
	return uint64(unsafe.Sizeof(uint32(o)))
}

func (o HopLimit) Marshal(b []byte) {
	*(*uint32)(unsafe.Pointer(&b[0])) = uint32(o)
}

func (o *HopLimit) Unmarshal(b []byte) {
	*o = HopLimit(*(*uint32)(unsafe.Pointer(&b[0])))
}

type recvHopLimit bool

func (o recvHopLimit) Level() int32 {
	return unix.SOL_IPV6
}

func (o recvHopLimit) Type() int32 {
	return unix.IPV6_RECVHOPLIMIT
}

func (o recvHopLimit) Len() uint64 {
	return uint64(unsafe.Sizeof(int32(0)))
}

func (o recvHopLimit) Marshal(b []byte) {
	marshalBoolAsInt32(b, bool(o))
}

func (o *recvHopLimit) Unmarshal(b []byte) {
	*o = recvHopLimit(unmarshalBoolFromInt32(b))
}

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

type TrafficClass uint8

func (o TrafficClass) Level() int32 {
	return unix.SOL_IPV6
}

func (o TrafficClass) Type() int32 {
	return unix.IPV6_TCLASS
}

func (o TrafficClass) Len() uint64 {
	return uint64(unsafe.Sizeof(uint32(o)))
}

func (o TrafficClass) Marshal(b []byte) {
	*(*uint32)(unsafe.Pointer(&b[0])) = uint32(o)
}

func (o *TrafficClass) Unmarshal(b []byte) {
	*o = TrafficClass(*(*uint32)(unsafe.Pointer(&b[0])))
}

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

type Mark int32

func (o Mark) Level() int32 {
	return unix.SOL_SOCKET
}

func (o Mark) Type() int32 {
	return unix.SO_MARK
}

func (o Mark) Len() uint64 {
	return uint64(unsafe.Sizeof(o))
}

func (o Mark) Marshal(b []byte) {
	*(*Mark)(unsafe.Pointer(&b[0])) = o
}

func (o *Mark) Unmarshal(b []byte) {
	*o = *(*Mark)(unsafe.Pointer(&b[0]))
}

type recvErr bool

func (o recvErr) Level() int32 {
	return unix.SOL_IP
}

func (o recvErr) Type() int32 {
	return unix.IP_RECVERR
}

func (o recvErr) Len() uint64 {
	return uint64(unsafe.Sizeof(int32(0)))
}

func (o recvErr) Marshal(b []byte) {
	marshalBoolAsInt32(b, bool(o))
}

func (o *recvErr) Unmarshal(b []byte) {
	*o = recvErr(unmarshalBoolFromInt32(b))
}

type recvErr6 bool

func (o recvErr6) Level() int32 {
	return unix.SOL_IPV6
}

func (o recvErr6) Type() int32 {
	return unix.IPV6_RECVERR
}

func (o recvErr6) Len() uint64 {
	return uint64(unsafe.Sizeof(int32(0)))
}

func (o recvErr6) Marshal(b []byte) {
	marshalBoolAsInt32(b, bool(o))
}

func (o *recvErr6) Unmarshal(b []byte) {
	*o = recvErr6(unmarshalBoolFromInt32(b))
}

type timestampNs bool

func (o timestampNs) Level() int32 {
	return unix.SOL_SOCKET
}

func (o timestampNs) Type() int32 {
	return unix.SO_TIMESTAMPNS_NEW
}

func (o timestampNs) Len() uint64 {
	return uint64(unsafe.Sizeof(int32(0)))
}

func (o timestampNs) Marshal(b []byte) {
	*(*int32)(unsafe.Pointer(&b[0])) = b2i(bool(o))
}

func (o *timestampNs) Unmarshal(b []byte) {
	*o = timestampNs(i2b(*(*int32)(unsafe.Pointer(&b[0]))))
}

type timestamping int32

func (o timestamping) Level() int32 {
	return unix.SOL_SOCKET
}

func (o timestamping) Type() int32 {
	// TODO: OLD?
	return unix.SO_TIMESTAMPING_NEW
}

func (o timestamping) Len() uint64 {
	return uint64(unsafe.Sizeof(int32(0)))
}

func (o timestamping) Marshal(b []byte) {
	*(*int32)(unsafe.Pointer(&b[0])) = int32(o)
}

func (o *timestamping) Unmarshal(b []byte) {
	*o = timestamping(*(*int32)(unsafe.Pointer(&b[0])))
}

func b2i(b bool) int32 {
	if b {
		return 1
	}
	return 0
}

func i2b(i int32) bool {
	return i != 0
}
