package ping

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
	_   [4]byte
}

func recvmmsg(s uintptr, hs []mmsghdr, flags int) (int, error) {
	n, _, errno := syscall.Syscall6(unix.SYS_RECVMMSG, s, uintptr(unsafe.Pointer(&hs[0])),
		uintptr(len(hs)), uintptr(flags), 0, 0)
	return int(n), unix.Errno(errno)
}
