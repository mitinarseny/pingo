package unix

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

func NewMsghdr(sa, p, oob []byte) unix.Msghdr {
	var msg unix.Msghdr
	if len(sa) > 0 {
		msg.Name = (*byte)(unsafe.Pointer(&sa[0]))
		msg.Namelen = uint32(len(sa))
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

func NewMmsghdr(sa, p, oob []byte) Mmsghdr {
	return Mmsghdr{
		Hdr: NewMsghdr(sa, p, oob),
	}
}

func MakeMmsghdr(family int, n, oobn int) (sa, p, oob []byte, h Mmsghdr) {
	if n > 0 {
		p = make([]byte, n)
	}
	if oobn > 0 {
		oob = make([]byte, oobn)
	}
	if family != unix.AF_UNSPEC {
		sa = make([]byte, SockaddrLen(family))
	}
	return sa, p, oob, NewMmsghdr(sa, p, oob)
}

func MakeMmsghdrs(family int, n, pn, oobn int) (sas, ps, oobs [][]byte, hs []Mmsghdr) {
	hs = make([]Mmsghdr, 0, n)
	sas = make([][]byte, 0, n)
	ps = make([][]byte, 0, n)
	oobs = make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		sa, p, oob, h := MakeMmsghdr(family, pn, oobn)
		hs = append(hs, h)
		sas = append(sas, sa)
		ps = append(ps, p)
		oobs = append(oobs, oob)
	}
	return sas, ps, oobs, hs
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

func SockaddrLen(family int) uint32 {
	switch family {
	case unix.AF_NETLINK:
		return unix.SizeofSockaddrNetlink
	case unix.AF_UNIX:
		return unix.SizeofSockaddrUnix
	case unix.AF_PACKET:
		return unix.SizeofSockaddrLinklayer
	case unix.AF_INET:
		return unix.SizeofSockaddrInet4
	case unix.AF_INET6:
		return unix.SizeofSockaddrInet6
	case unix.AF_VSOCK:
		return unix.SizeofSockaddrVM
	case unix.AF_TIPC:
		return unix.SizeofSockaddrTIPC
	case unix.AF_BLUETOOTH:
		return unix.SizeofSockaddrL2 // TODO: unix.SockaddrRFCOMM
	case unix.AF_XDP:
		return unix.SizeofSockaddrXDP
	case unix.AF_PPPOX:
		return unix.SizeofSockaddrPPPoX
	case unix.AF_IUCV:
		return unix.SizeofSockaddrIUCV
	case unix.AF_CAN:
		return unix.SizeofSockaddrCAN
	case unix.AF_NFC:
		return unix.SizeofSockaddrNFC // TODO: unix.SockaddrNFCLLCP
	default:
		panic(unix.EINVAL)
	}
}

// sockaddr copies behaviour of unix.Sockadd.sockaddr()
func sockaddr(sa unix.Sockaddr) (ptr unsafe.Pointer, l uint32) {
	switch sa := sa.(type) {
	case *unix.SockaddrNetlink:
		return unsafe.Pointer(&unix.RawSockaddrNetlink{
			Family: sa.Family,
			Pad:    sa.Pad,
			Pid:    sa.Pid,
			Groups: sa.Groups,
		}), unix.SizeofSockaddrNetlink
	case *unix.SockaddrUnix:
		r := unix.RawSockaddrUnix{
			Family: unix.AF_UNIX,
		}
		copy((*[len(r.Path)]byte)(unsafe.Pointer(&r.Path[0]))[:], sa.Name)
		return unsafe.Pointer(&r), unix.SizeofSockaddrUnix
	case *unix.SockaddrLinklayer:
		return unsafe.Pointer(&unix.RawSockaddrLinklayer{
			Family:   unix.AF_PACKET,
			Protocol: sa.Protocol,
			Ifindex:  int32(sa.Ifindex),
			Hatype:   sa.Hatype,
			Pkttype:  sa.Pkttype,
			Halen:    sa.Halen,
			Addr:     sa.Addr,
		}), unix.SizeofSockaddrLinklayer
	case *unix.SockaddrInet4:
		return unsafe.Pointer(&unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Port:   uint16(sa.Port),
			Addr:   sa.Addr,
		}), unix.SizeofSockaddrInet4
	case *unix.SockaddrInet6:
		return unsafe.Pointer(&unix.RawSockaddrInet6{
			Family:   unix.AF_INET6,
			Port:     uint16(sa.Port),
			Addr:     sa.Addr,
			Flowinfo: sa.ZoneId,
		}), unix.SizeofSockaddrInet4
	case *unix.SockaddrVM:
		return unsafe.Pointer(&unix.RawSockaddrVM{
			Family: unix.AF_VSOCK,
			Port:   sa.Port,
			Cid:    sa.CID,
			Flags:  sa.Flags,
		}), unix.SizeofSockaddrVM
	case *unix.SockaddrTIPC:
		r := unix.RawSockaddrTIPC{
			Family: unix.AF_TIPC,
			Scope:  int8(sa.Scope),
		}
		switch addr := sa.Addr.(type) {
		case *unix.TIPCSocketAddr:
			r.Addrtype = unix.TIPC_SOCKET_ADDR
			*(*unix.TIPCSocketAddr)(unsafe.Pointer(&r.Addr[0])) = *addr
		case *unix.TIPCServiceRange:
			r.Addrtype = unix.TIPC_SERVICE_RANGE
			*(*unix.TIPCServiceRange)(unsafe.Pointer(&r.Addr[0])) = *addr
		case *unix.TIPCServiceName:
			r.Addrtype = unix.TIPC_SERVICE_ADDR
			*(*unix.TIPCServiceName)(unsafe.Pointer(&r.Addr[0])) = *addr
		}
		return unsafe.Pointer(&r), unix.SizeofSockaddrTIPC
	case *unix.SockaddrL2:
		return unsafe.Pointer(&unix.RawSockaddrL2{
			Family:      unix.AF_BLUETOOTH,
			Psm:         sa.PSM,
			Bdaddr:      sa.Addr,
			Cid:         sa.CID,
			Bdaddr_type: sa.AddrType,
		}), unix.SizeofSockaddrL2
	case *unix.SockaddrRFCOMM:
		return unsafe.Pointer(&unix.RawSockaddrRFCOMM{
			Family:  unix.AF_BLUETOOTH,
			Bdaddr:  sa.Addr,
			Channel: sa.Channel,
		}), unix.SizeofSockaddrRFCOMM
	case *unix.SockaddrXDP:
		return unsafe.Pointer(&unix.RawSockaddrXDP{
			Family:         unix.AF_XDP,
			Flags:          sa.Flags,
			Ifindex:        sa.Ifindex,
			Queue_id:       sa.QueueID,
			Shared_umem_fd: sa.SharedUmemFD,
		}), unix.SizeofSockaddrXDP
	case *unix.SockaddrPPPoE:
		var r unix.RawSockaddrPPPoX
		if len(sa.Remote) != 6 {
			panic(unix.EINVAL)
		}
		if len(sa.Dev) > unix.IFNAMSIZ-1 {
			panic(unix.EINVAL)
		}
		*(*uint16)(unsafe.Pointer(&r[0])) = unix.AF_PPPOX
		// This next field is in host-endian byte order. We can't use the
		// same unsafe pointer cast as above, because this value is not
		// 32-bit aligned and some architectures don't allow unaligned
		// access.
		//
		// However, the value of px_proto_oe is 0, so we can use
		// encoding/binary helpers to write the bytes without worrying
		// about the ordering.
		binary.BigEndian.PutUint32(r[2:6], 0)
		// This field is deliberately big-endian, unlike the previous
		// one. The kernel expects SID to be in network byte order.
		binary.BigEndian.PutUint16(r[6:8], sa.SID)
		copy(r[8:14], sa.Remote)
		for i := 14; i < 14+unix.IFNAMSIZ; i++ {
			r[i] = 0
		}
		copy(r[14:], sa.Dev)
		return unsafe.Pointer(&r), unix.SizeofSockaddrPPPoX
	case *unix.SockaddrIUCV:
		r := unix.RawSockaddrIUCV{
			Family: unix.AF_IUCV,
		}
		blank := [len(r.Nodeid)]int8{' '}
		copy(r.Nodeid[:], blank[:])
		copy(r.User_id[:], blank[:])
		copy(r.Name[:], blank[:])
		if len(sa.UserID) > len(r.User_id) || len(sa.Name) > len(r.Name) {
			panic(unix.EINVAL)
		}
		copy((*[len(r.User_id)]byte)(unsafe.Pointer(&r.User_id[0]))[:], []byte(sa.UserID))
		copy((*[len(r.Name)]byte)(unsafe.Pointer(&r.Name[0]))[:], []byte(sa.Name))
		return unsafe.Pointer(&r), unix.SizeofSockaddrIUCV
	case *unix.SockaddrCAN:
		r := unix.RawSockaddrCAN{
			Family:  unix.AF_CAN,
			Ifindex: int32(sa.Ifindex),
		}
		*(*uint32)(unsafe.Pointer(&r.Addr[0])) = sa.RxID
		*(*uint32)(unsafe.Pointer(&r.Addr[unsafe.Sizeof(uint32(0))])) = sa.TxID
		return unsafe.Pointer(&r), unix.SizeofSockaddrCAN
	case *unix.SockaddrCANJ1939:
		r := unix.RawSockaddrCAN{
			Family:  unix.AF_CAN,
			Ifindex: int32(sa.Ifindex),
		}
		*(*uint64)(unsafe.Pointer(&r.Addr[0])) = sa.Name
		*(*uint32)(unsafe.Pointer(&r.Addr[unsafe.Sizeof(uint64(0))])) = sa.PGN
		r.Addr[unsafe.Sizeof(uint64(0))+unsafe.Sizeof(uint32(0))] = sa.Addr
		return unsafe.Pointer(&r), unix.SizeofSockaddrCAN
	case *unix.SockaddrNFC:
		return unsafe.Pointer(&unix.RawSockaddrNFC{
			Sa_family:    unix.AF_NFC,
			Dev_idx:      sa.DeviceIdx,
			Target_idx:   sa.TargetIdx,
			Nfc_protocol: sa.NFCProtocol,
		}), unix.SizeofSockaddrNFC
	case *unix.SockaddrNFCLLCP:
		r := unix.RawSockaddrNFCLLCP{
			Sa_family:        unix.AF_NFC,
			Dev_idx:          sa.DeviceIdx,
			Target_idx:       sa.TargetIdx,
			Nfc_protocol:     sa.NFCProtocol,
			Dsap:             sa.DestinationSAP,
			Ssap:             sa.SourceSAP,
			Service_name:     [63]uint8{},
			Service_name_len: uint64(len(sa.ServiceName)),
		}
		if len(sa.ServiceName) > len(r.Service_name) {
			panic(unix.EINVAL)
		}
		copy(r.Service_name[:], sa.ServiceName)
		return unsafe.Pointer(&r), unix.SizeofSockaddrNFCLLCP
	default:
		panic(fmt.Errorf("unknown Sockaddr: %#T", sa))
	}
}
