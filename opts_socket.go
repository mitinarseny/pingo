package ping

import (
	unixx "github.com/mitinarseny/pingo/unix"
	"golang.org/x/sys/unix"
)

// Mark is <SOL_SOCKET, SO_MARK>
func Mark(m uint32) *unixx.IntegerSockOpt[uint32] {
	return unixx.NewIntegerSockOpt[uint32](unix.SOL_SOCKET, unix.SO_MARK).Set(m)
}

// timestampNs is <SOL_SOLKET, SO_TIMESTAMPNS>
func timestampNs(v bool) *unixx.IntegerSockOpt[bool] {
	return unixx.NewIntegerSockOpt[bool](unix.SOL_SOCKET, unix.SO_TIMESTAMPNS).Set(v)
}

// timestamping is <SOL_SOCKET, SO_TIMESTAMPING>
func timestamping(flags int32) *unixx.IntegerSockOpt[int32] {
	return unixx.NewIntegerSockOpt[int32](unix.SOL_SOCKET, unix.SO_TIMESTAMPING).Set(flags)
}
