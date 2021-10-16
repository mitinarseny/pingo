package ping

import (
	"unsafe"

	unixx "github.com/mitinarseny/pingo/unix"
	"golang.org/x/sys/unix"
)

// makeMmsghdrs makes and returns n mmsghdrs and their underlying buffers
// of lengths pn and oobn correspondingly
func makeMmsghdrs(n, pn, oobn int) (ps, oobs [][]byte, hs []unixx.Mmsghdr) {
	ps = make([][]byte, n)
	oobs = make([][]byte, n)
	for i := 0; i < n; i++ {
		ps[i] = make([]byte, pn)
		oobs[i] = make([]byte, oobn)
	}
	return ps, oobs, newMmsghdrs(ps, oobs)
}

// newMmsghdrs returns mmsghdrs, which buffers points to given ones
func newMmsghdrs(ps, oobs [][]byte) []unixx.Mmsghdr {
	if len(ps) != len(oobs) {
		panic("mismatching lengths of buffers")
	}
	hs := make([]unixx.Mmsghdr, len(ps))
	for i := 0; i < len(hs); i++ {
		hs[i].Hdr = newMsghdr(ps[i], oobs[i])
	}
	return hs
}

// see unix.Recvmsg
func newMsghdr(p, oob []byte) unix.Msghdr {
	var msg unix.Msghdr
	var rsa unix.RawSockaddrAny
	msg.Name = (*byte)(unsafe.Pointer(&rsa))
	msg.Namelen = uint32(unix.SizeofSockaddrAny)
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
