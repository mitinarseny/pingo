package ping

import (
	unixx "github.com/mitinarseny/pingo/unix"
	"golang.org/x/sys/unix"
)

// MTU is <SOL_IP, IP_MTU>
func MTU(mtu int32) *unixx.IntegerSockOpt[int32] {
	return unixx.NewIntegerSockOpt[int32](unix.SOL_IP, unix.IP_MTU).Set(mtu)
}

// MTU6 is <SOL_IPV6, IPV6_MTU>
func MTU6(mtu int32) *unixx.IntegerSockOpt[int32] {
	return unixx.NewIntegerSockOpt[int32](unix.SOL_IPV6, unix.IPV6_MTU).Set(mtu)
}

// TTL is <SOL_IP, IP_TTL>
func TTL(ttl uint8) *unixx.IntegerSockOpt[uint8] {
	return unixx.NewIntegerSockOpt[uint8](unix.SOL_IP, unix.IP_TTL).Set(ttl)
}

// TTL is <SOL_IPV6, IPV6_HOPLIMIT>
func HopLimit(hl uint8) *unixx.IntegerSockOpt[uint8] {
	return unixx.NewIntegerSockOpt[uint8](unix.SOL_IPV6, unix.IPV6_HOPLIMIT).Set(hl)
}

// TrafficClass is <SOL_IPV6, IPV6_TCLASS>
func TrafficClass(tc uint8) *unixx.IntegerSockOpt[uint8] {
	return unixx.NewIntegerSockOpt[uint8](unix.SOL_IPV6, unix.IPV6_TCLASS).Set(tc)
}

// recvErr is <SOL_IP, IP_RECVERR>
func recvErr(v bool) *unixx.IntegerSockOpt[bool] {
	return unixx.NewIntegerSockOpt[bool](unix.SOL_IP, unix.IP_RECVERR).Set(v)
}

// recvErr6 is <SOL_IPV6, IPV6_RECVERR>
func recvErr6(v bool) *unixx.IntegerSockOpt[bool] {
	return unixx.NewIntegerSockOpt[bool](unix.SOL_IPV6, unix.IPV6_RECVERR).Set(v)
}

// recvTTL is <SOL_IP, IP_RECVTTL>
func recvTTL(v bool) *unixx.IntegerSockOpt[bool] {
	return unixx.NewIntegerSockOpt[bool](unix.SOL_IP, unix.IP_RECVTTL).Set(v)
}

// recvHopLimit is <SOL_IPV6, IPV6_RECVHOPLIMIT>
func recvHopLimit(v bool) *unixx.IntegerSockOpt[bool] {
	return unixx.NewIntegerSockOpt[bool](unix.SOL_IPV6, unix.IPV6_RECVHOPLIMIT).Set(v)
}
