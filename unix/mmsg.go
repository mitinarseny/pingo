package unix

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

func NewMsghdr(name, p, oob []byte) unix.Msghdr {
	var msg unix.Msghdr
	if len(name) > 0 {
		msg.Name = (*byte)(unsafe.Pointer(&name[0]))
		msg.Namelen = uint32(len(name))
	}
	var iov unix.Iovec
	if len(p) > 0 {
		iov.Base = &p[0]
		iov.SetLen(len(p))
	}
	if len(oob) > 0 {
		msg.Control = &oob[0]
		msg.SetControllen(len(oob))
	}
	msg.Iov = &iov
	msg.Iovlen = 1
	return msg
}

type Mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
	_   [4]byte
}

func NewMmsghdr(name, p, oob []byte) Mmsghdr {
	return Mmsghdr{
		Hdr: NewMsghdr(name, p, oob),
	}
}

func MakeMmsghdr(namelen, n, oobn int) (name unsafe.Pointer, p, oob []byte, h Mmsghdr) {
	p, oob = make([]byte, n), make([]byte, oobn)
	var nameb []byte
	if namelen > 0 {
		nameb := make([]byte, namelen)
		name = unsafe.Pointer(&nameb[0])
	}
	return name, p, oob, NewMmsghdr(nameb, p, oob)
}

func MakeMmsghdrs(n, namelen, pn, oobn int) (names []unsafe.Pointer, ps, oobs [][]byte, hs []Mmsghdr) {
	ps, oobs = make([][]byte, 0, n), make([][]byte, 0, n)
	names = make([]unsafe.Pointer, 0, n)
	hs = make([]Mmsghdr, 0, n)
	for i := 0; i < n; i++ {
		name, p, oob, h := MakeMmsghdr(namelen, pn, oobn)
		names = append(names, name)
		ps = append(ps, p)
		oobs = append(oobs, oob)
		hs = append(hs, h)
	}
	return names, ps, oobs, hs
}

func Recvmmsg(s uintptr, hs []Mmsghdr, flags int) (int, error) {
	n, _, errno := unix.Syscall6(unix.SYS_RECVMMSG, s, uintptr(unsafe.Pointer(&hs[0])),
		uintptr(len(hs)), uintptr(flags), 0, 0)
	return int(n), errnoErr(errno)
}

func Sendmmsg(s uintptr, hs []Mmsghdr, flags int) (int, error) {
	n, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, s, uintptr(unsafe.Pointer(&hs[0])),
		uintptr(len(hs)), uintptr(flags), 0, 0)
	return int(n), errnoErr(errno)
}
