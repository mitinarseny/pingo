package unix

import (
	"os"
	"unsafe"

	"golang.org/x/exp/constraints"
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

type PointerSockOpt struct {
	sockopt
	length uint32
	ptr    unsafe.Pointer
}

var _ SockOpt = &PointerSockOpt{}

func NewPointerSockOpt(lvl, typ int32) *PointerSockOpt {
	return &PointerSockOpt{
		sockopt: sockopt{
			lvl: lvl,
			typ: typ,
		},
	}
}

func (o PointerSockOpt) Len() uint32 {
	return o.length
}

func (o *PointerSockOpt) Ptr() unsafe.Pointer {
	return o.ptr
}

func (o *PointerSockOpt) setLen(l uint32) {
	o.length = l
}

func (o *PointerSockOpt) bytes() []byte {
	return unsafe.Slice((*byte)(o.Ptr()), o.Len())
}

func (o *PointerSockOpt) Set(length uint32, ptr unsafe.Pointer) *PointerSockOpt {
	o.length = length
	o.ptr = ptr
	return o
}

// IntegerSockOpt is a read/write (get/set)sockopt option
type IntegerSockOpt[T constraints.Integer | ~bool] struct {
	sockopt
	value T
}

var _ SockOpt = &IntegerSockOpt[int]{}

func NewIntegerSockOpt[T constraints.Integer | ~bool](lvl, typ int32) *IntegerSockOpt[T] {
	return &IntegerSockOpt[T]{
		sockopt: sockopt{
			lvl: lvl,
			typ: typ,
		},
	}
}

func (o IntegerSockOpt[T]) Len() uint32 {
	return uint32(unsafe.Sizeof(o.value))
}

func (o *IntegerSockOpt[T]) Ptr() unsafe.Pointer {
	return unsafe.Pointer(&o.value)
}

func (o *IntegerSockOpt[T]) setLen(uint32) {}

func (o *IntegerSockOpt[T]) bytes() []byte {
	return unsafe.Slice((*byte)(o.Ptr()), o.Len())
}

func (o IntegerSockOpt[T]) Get() T {
	return o.value
}

func (o *IntegerSockOpt[T]) Set(v T) *IntegerSockOpt[T] {
	o.value = v
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
