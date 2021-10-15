package syscall

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

type Mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
	_   [4]byte // TODO: rm?
}

func NewMmsghdrs(bs [][]byte, oobs [][]byte, sas [][]byte, flags []int) []Mmsghdr {
	hs := make([]Mmsghdr, len(bs))
	for i := range bs {
		hs[i].Hdr = *newMsghdr(bs[i], oobs[i], sas[i], flags[i])
	}
	return hs
}

func newMsghdr(p []byte, oob []byte, sa []byte, flags int) *unix.Msghdr {
	var h unix.Msghdr
	if sa != nil {
		h.Name = (*byte)(unsafe.Pointer(&sa[0]))
		h.Namelen = uint32(len(sa))
	}
	h.Iov = new(unix.Iovec)
	h.SetIovlen(1)
	if len(p) > 0 {
		h.Iov.Base = &p[0]
		h.Iov.SetLen(len(p))
	}
	if len(oob) > 0 {
		if len(p) == 0 {
			// assume socket type is SOCK_DGRAM
			var dummy byte
			h.Iov.Base = &dummy
			h.Iov.SetLen(1)
		}
		h.Control = &oob[0]
		h.SetControllen(len(oob))
	}
	h.Flags = int32(flags)
	return &h
}

func Recvmmsg(s int, hs []Mmsghdr, flags int) (int, error) {
	n, _, errno := unix.Syscall6(unix.SYS_RECVMMSG, uintptr(s), uintptr(unsafe.Pointer(&hs[0])),
		uintptr(len(hs)), uintptr(flags), 0, 0)
	return int(n), errnoErr(errno)
}

func errnoErr(e unix.Errno) error {
	if e == 0 {
		return nil
	}
	return e
}
