package unix

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

func connect(s uintptr, addr unsafe.Pointer, addrlen uint32) error {
	_, _, e := unix.Syscall(unix.SYS_CONNECT, s, uintptr(addr), uintptr(addrlen))
	return errnoErr(e)
}

// Disconnect calls connect(2) to AF_UNSPEC. See man 2 connect for details.
func Disconnect(s uintptr) error {
	return connect(s, unsafe.Pointer(&unix.RawSockaddrInet4{
		Family: unix.AF_UNSPEC,
	}), unix.SizeofSockaddrInet4)
}
