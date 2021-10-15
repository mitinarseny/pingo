package ping

import "golang.org/x/sys/unix"

func Mark(m int32) Int32Option {
	return NewInt32Option(unix.SOL_SOCKET, unix.SO_MARK).Set(m)
}

func timestampNs(v bool) BoolOption {
	return NewBoolOption(unix.SOL_SOCKET, unix.SO_TIMESTAMPNS).Set(v)
}

func timestamping(flags int32) Int32Option {
	return NewInt32Option(unix.SOL_SOCKET, unix.SO_TIMESTAMPING).Set(flags)
}
