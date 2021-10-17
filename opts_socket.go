package ping

import "golang.org/x/sys/unix"

// Mark is <SOL_SOCKET, SO_MARK>
func Mark(m uint32) Uint32Option {
	return NewUint32Option(unix.SOL_SOCKET, unix.SO_MARK).Set(m)
}

// timestampNs is <SOL_SOLKET, SO_TIMESTAMPNS>
func timestampNs(v bool) BoolOption {
	return NewBoolOption(unix.SOL_SOCKET, unix.SO_TIMESTAMPNS).Set(v)
}

// timestamping is <SOL_SOCKET, SO_TIMESTAMPING>
func timestamping(flags int32) Int32Option {
	return NewInt32Option(unix.SOL_SOCKET, unix.SO_TIMESTAMPING).Set(flags)
}
