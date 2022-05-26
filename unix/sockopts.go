package unix

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// SockOpt is a socket option
type SockOpt interface {
	Level() int32
	Type() int32
	// Len returns length of option value in bytes
	Len() uint32
	Ptr() unsafe.Pointer

	setLen(uint32)
	bytes() []byte
}

func GetSockOpts(fd uintptr, opts ...SockOpt) error {
	for _, o := range opts {
		l := o.Len()
		_, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, uintptr(o.Level()), uintptr(o.Type()),
			uintptr(o.Ptr()), uintptr(unsafe.Pointer(&l)), 0)
		if e != 0 {
			return os.NewSyscallError("getsockopt", unix.Errno(e))
		}
		o.setLen(l)
	}
	return nil
}

func SetSockOpts(fd uintptr, opts ...SockOpt) error {
	for _, o := range opts {
		_, _, e := unix.Syscall6(unix.SYS_SETSOCKOPT, fd, uintptr(o.Level()), uintptr(o.Type()),
			uintptr(o.Ptr()), uintptr(o.Len()), 0)
		if e != 0 {
			return os.NewSyscallError("setsockopt", unix.Errno(e))
		}
	}
	return nil
}

func MarshalOpt(b []byte, o SockOpt) {
	copy(b, o.bytes())
}

func UnmarshalOpt(b []byte, o SockOpt) {
	copy(o.bytes(), b)
}

func MarshalCmsg(opts ...SockOpt) []byte {
	if len(opts) == 0 {
		return nil
	}
	var l int
	for _, o := range opts {
		l += unix.CmsgSpace(int(o.Len()))
	}
	b := make([]byte, l)
	bb := b
	for _, o := range opts {
		h := (*unix.Cmsghdr)(unsafe.Pointer(&bb[0]))
		h.Level = o.Level()
		h.Type = o.Type()
		h.Len = uint64(unix.CmsgLen(int(o.Len())))
		MarshalOpt(bb[unix.CmsgLen(0):h.Len], o)
		bb = bb[unix.CmsgSpace(int(o.Len())):]
	}
	return b
}

type sockopt struct {
	lvl, typ int32
}

func (o *sockopt) Level() int32 {
	return o.lvl
}

func (o *sockopt) Type() int32 {
	return o.typ
}

type ValueSockOpt[T any] struct {
	sockopt
	value T
}

var _ SockOpt = &ValueSockOpt[int]{}

func NewSockOpt[T any](lvl, typ int32) *ValueSockOpt[T] {
	return &ValueSockOpt[T]{
		sockopt: sockopt{
			lvl: lvl,
			typ: typ,
		},
	}
}

func (o *ValueSockOpt[T]) Len() uint32 {
	var tmp T
	return uint32(unsafe.Sizeof(tmp))
}

func (o *ValueSockOpt[T]) Ptr() unsafe.Pointer {
	return unsafe.Pointer(&o.value)
}

func (o *ValueSockOpt[T]) setLen(uint32) {}

func (o *ValueSockOpt[T]) bytes() []byte {
	return unsafe.Slice((*byte)(o.Ptr()), o.Len())
}

func (o *ValueSockOpt[T]) Get() T {
	return o.value
}

func (o *ValueSockOpt[T]) Set(v T) *ValueSockOpt[T] {
	o.value = v
	return o
}

type BoolSockOpt struct {
	*ValueSockOpt[int32]
}

func NewBoolSockOpt(lvl, typ int32) BoolSockOpt {
	return BoolSockOpt{NewSockOpt[int32](lvl, typ)}
}

func (o BoolSockOpt) Get() bool {
	return o.ValueSockOpt.Get() != 0
}

func (o BoolSockOpt) Set(v bool) BoolSockOpt {
	var i int32
	if v {
		i = 1
	}
	o.ValueSockOpt.Set(i)
	return o
}

type bytes interface {
	~[]byte | string
}

type BytesSockOpt[T bytes] struct {
	sockopt
	value T
}

var _ SockOpt = &BytesSockOpt[[]byte]{}

func NewBytesSockOpt[T bytes](lvl, typ int32) *BytesSockOpt[T] {
	return &BytesSockOpt[T]{
		sockopt: sockopt{
			lvl: lvl,
			typ: typ,
		},
	}
}

func (o BytesSockOpt[T]) Len() uint32 {
	return uint32(len(o.value))
}

func (o BytesSockOpt[T]) Ptr() unsafe.Pointer {
	return unsafe.Pointer(&[]byte(o.value)[0])
}

func (o *BytesSockOpt[T]) setLen(l uint32) {
	o.Set(T(make([]byte, l)))
}

func (o BytesSockOpt[T]) bytes() []byte {
	return []byte(o.value)
}

func (o BytesSockOpt[T]) Get() T {
	return o.value
}

func (o *BytesSockOpt[T]) Set(v T) *BytesSockOpt[T] {
	o.value = v
	return o
}

func (o *BytesSockOpt[T]) SetSize(size int) *BytesSockOpt[T] {
	o.setLen(uint32(size))
	return o
}
