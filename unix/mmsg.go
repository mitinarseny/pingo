package unix

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

type Mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
	_   [4]byte
}

func Recvmmsg(s uintptr, hs []Mmsghdr, flags int) (int, error) {
	n, _, errno := unix.Syscall6(unix.SYS_RECVMMSG, s, uintptr(unsafe.Pointer(&hs[0])),
		uintptr(len(hs)), uintptr(flags), 0, 0)
	return int(n), errnoErr(errno)
}
