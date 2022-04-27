package unix

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// SockOpt is a socket option
type SockOpt interface {
	Level() int32
	Type() int32
	// Len returns length of option value in bytes
	Len() uint64
}

// RSockOpt is a read getsockopt option
type RSockOpt interface {
	SockOpt
	// Unmarshal decodes option from given buffer.
	// If length of given buffer is less than Len(),
	// it should not panic if possible
	Unmarshal([]byte)
}

func GetSockOpts(fd uintptr, opts ...RSockOpt) error {
	for _, o := range opts {
		var s string
		s, err := unix.GetsockoptString(int(fd), int(o.Level()), int(o.Type()))
		if err != nil {
			return os.NewSyscallError("getsockopt", err)
		}
		o.Unmarshal([]byte(s))
	}
	return nil
}

// WSockOpt is a write setsockopt option
type WSockOpt interface {
	SockOpt
	// Marshal encodes option to the given buffer.
	// Length of given buffer should be not less than Len()
	Marshal([]byte)
}

func SetSockOpts(fd uintptr, opts ...WSockOpt) error {
	for _, o := range opts {
		b := make([]byte, o.Len())
		o.Marshal(b)
		if err := unix.SetsockoptString(int(fd), int(o.Level()),
			int(o.Type()), string(b)); err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
	}
	return nil
}

func MarshalCmsg(opts ...WSockOpt) []byte {
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
		o.Marshal(bb[unix.CmsgLen(0):h.Len])
		bb = bb[unix.CmsgSpace(int(o.Len())):]
	}
	return b
}

// RWSockOpt is a read/write (get/set)sockopt option
type RWSockOpt interface {
	RSockOpt
	WSockOpt
}

type sockopt struct {
	lvl    int32
	typ    int32
	length uintptr
	p      unsafe.Pointer
}

func NewSockOpt(lvl, typ int32, length uintptr, p unsafe.Pointer) *sockopt {
	return &sockopt{
		lvl:    lvl,
		typ:    typ,
		length: length,
		p:      p,
	}
}

func (o *sockopt) Level() int32 {
	return o.lvl
}

func (o *sockopt) Type() int32 {
	return o.typ
}

func (o *sockopt) Len() uint64 {
	return uint64(o.length)
}

func (o *sockopt) Value() unsafe.Pointer {
	return o.p
}

func (o *sockopt) Marshal(b []byte) {
	if uint64(len(b)) < o.Len() {
		panic(fmt.Errorf("marshal to buffer of insufficient length: %d, want: %d",
			len(b), o.length))
	}
	copyP(unsafe.Pointer(&b[0]), o.p, o.length)
}

func (o *sockopt) Unmarshal(b []byte) {
	copyP(o.p, unsafe.Pointer(&b[0]), min(uintptr(len(b)), o.length))
}

// copyP copies l bytes from [src, src + l) t-o [dst, dst + l)
func copyP(dst, src unsafe.Pointer, l uintptr) {
	var s uintptr
	for l > 0 {
		if l >= unsafe.Sizeof(uint64(0)) {
			s = unsafe.Sizeof(uint64(0))
			*(*uint64)(dst) = *(*uint64)(src)
		} else if l >= unsafe.Sizeof(uint32(0)) {
			s = unsafe.Sizeof(uint32(0))
			*(*uint32)(dst) = *(*uint32)(src)
		} else if l >= unsafe.Sizeof(uint16(0)) {
			s = unsafe.Sizeof(uint16(0))
			*(*uint16)(dst) = *(*uint16)(src)
		} else {
			s = unsafe.Sizeof(uint8(0))
			*(*uint8)(dst) = *(*uint8)(src)
		}
		l -= s
		dst, src = unsafe.Pointer(uintptr(dst)+s), unsafe.Pointer(uintptr(src)+s)
	}
}

func min(x, y uintptr) uintptr {
	if x < y {
		return x
	}
	return y
}

type BoolSockOpt interface {
	RWSockOpt
	Get() bool
	Set(bool) BoolSockOpt
}

type boolSockOpt struct {
	*sockopt
}

func NewBoolSockOpt(lvl, typ int32) BoolSockOpt {
	return boolSockOpt{NewUint8SockOpt(lvl, typ).(uint8SockOpt).sockopt}
}

func (o boolSockOpt) Get() bool {
	return uint8SockOpt{o.sockopt}.Get() != 0
}

func (o boolSockOpt) Set(v bool) BoolSockOpt {
	var vv uint8
	if v {
		vv = 1
	}
	uint8SockOpt{o.sockopt}.Set(vv)
	return o
}

type IntSockOpt interface {
	RWSockOpt
	Get() int
	Set(int) IntSockOpt
}

type intSockOpt struct {
	*sockopt
}

func NewIntSockOpt(lvl, typ int32) IntSockOpt {
	v := new(int)
	return intSockOpt{NewSockOpt(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o intSockOpt) Get() int {
	return *(*int)(o.Value())
}

func (o intSockOpt) Set(v int) IntSockOpt {
	*(*int)(o.Value()) = v
	return o
}

type UintSockOpt interface {
	RWSockOpt
	Get() uint
	Set(uint) UintSockOpt
}

type uintSockOpt struct {
	*sockopt
}

func NewUintSockOpt(lvl, typ int32) UintSockOpt {
	v := new(uint)
	return uintSockOpt{NewSockOpt(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o uintSockOpt) Get() uint {
	return *(*uint)(o.Value())
}

func (o uintSockOpt) Set(v uint) UintSockOpt {
	*(*uint)(o.Value()) = v
	return o
}

type Int8SockOpt interface {
	RWSockOpt
	Get() int8
	Set(int8) Int8SockOpt
}

type int8SockOpt struct {
	*sockopt
}

func NewInt8SockOpt(lvl, typ int32) Int8SockOpt {
	v := new(int32)
	return int8SockOpt{NewSockOpt(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o int8SockOpt) Get() int8 {
	return int8(*(*int32)(o.Value()))
}

func (o int8SockOpt) Set(v int8) Int8SockOpt {
	*(*int32)(o.Value()) = int32(v)
	return o
}

type Uint8SockOpt interface {
	RWSockOpt
	Get() uint8
	Set(uint8) Uint8SockOpt
}

type uint8SockOpt struct {
	*sockopt
}

func NewUint8SockOpt(lvl, typ int32) Uint8SockOpt {
	v := new(uint32)
	return uint8SockOpt{NewSockOpt(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o uint8SockOpt) Get() uint8 {
	return uint8(*(*uint32)(o.Value()))
}

func (o uint8SockOpt) Set(v uint8) Uint8SockOpt {
	*(*uint32)(o.Value()) = uint32(v)
	return o
}

type Int16SockOpt interface {
	RWSockOpt
	Get() int16
	Set(int16) Int16SockOpt
}

type int16SockOpt struct {
	*sockopt
}

func NewInt16SockOpt(lvl, typ int32) Int16SockOpt {
	v := new(int32)
	return int16SockOpt{NewSockOpt(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o int16SockOpt) Get() int16 {
	return int16(*(*int32)(o.Value()))
}

func (o int16SockOpt) Set(v int16) Int16SockOpt {
	*(*int32)(o.Value()) = int32(v)
	return o
}

type Uint16SockOpt interface {
	RWSockOpt
	Get() uint16
	Set(uint16) Uint16SockOpt
}

type uint16SockOpt struct {
	*sockopt
}

func NewUint16SockOpt(lvl, typ int32) Uint16SockOpt {
	v := new(uint32)
	return uint16SockOpt{NewSockOpt(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o uint16SockOpt) Get() uint16 {
	return uint16(*(*uint32)(o.Value()))
}

func (o uint16SockOpt) Set(v uint16) Uint16SockOpt {
	*(*uint32)(o.Value()) = uint32(v)
	return o
}

type Int32SockOpt interface {
	RWSockOpt
	Get() int32
	Set(int32) Int32SockOpt
}

type int32SockOpt struct {
	*sockopt
}

func NewInt32SockOpt(lvl, typ int32) Int32SockOpt {
	v := new(int32)
	return int32SockOpt{NewSockOpt(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o int32SockOpt) Get() int32 {
	return *(*int32)(o.Value())
}

func (o int32SockOpt) Set(v int32) Int32SockOpt {
	*(*int32)(o.Value()) = v
	return o
}

type Uint32SockOpt interface {
	RWSockOpt
	Get() uint32
	Set(uint32) Uint32SockOpt
}

type uint32SockOpt struct {
	*sockopt
}

func NewUint32SockOpt(lvl, typ int32) Uint32SockOpt {
	v := new(uint32)
	return uint32SockOpt{NewSockOpt(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o uint32SockOpt) Get() uint32 {
	return *(*uint32)(o.Value())
}

func (o uint32SockOpt) Set(v uint32) Uint32SockOpt {
	*(*uint32)(o.Value()) = v
	return o
}

type Int64SockOpt interface {
	RWSockOpt
	Get() int64
	Set(int64) Int64SockOpt
}

type int64SockOpt struct {
	*sockopt
}

func NewInt64SockOpt(lvl, typ int32) Int64SockOpt {
	v := new(int64)
	return int64SockOpt{NewSockOpt(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o int64SockOpt) Get() int64 {
	return *(*int64)(o.Value())
}

func (o int64SockOpt) Set(v int64) Int64SockOpt {
	*(*int64)(o.Value()) = v
	return o
}

type Uint64SockOpt interface {
	RWSockOpt
	Get() uint64
	Set(uint64) Uint64SockOpt
}

type uint64SockOpt struct {
	*sockopt
}

func NewUint64SockOpt(lvl, typ int32) Uint64SockOpt {
	v := new(uint64)
	return uint64SockOpt{NewSockOpt(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o uint64SockOpt) Get() uint64 {
	return *(*uint64)(o.Value())
}

func (o uint64SockOpt) Set(v uint64) Uint64SockOpt {
	*(*uint64)(o.Value()) = v
	return o
}

type BytesSockOpt interface {
	RWSockOpt
	Get() []byte
	SetSize(int) BytesSockOpt
	Set([]byte) BytesSockOpt
}

type bytesSockOpt struct {
	lvl int32
	typ int32
	v   []byte
}

func NewBytesSockOpt(lvl, typ int32) BytesSockOpt {
	return &bytesSockOpt{
		lvl: lvl,
		typ: typ,
	}
}

func (o *bytesSockOpt) Level() int32 {
	return o.lvl
}

func (o *bytesSockOpt) Type() int32 {
	return o.typ
}

func (o *bytesSockOpt) Len() uint64 {
	return uint64(len(o.v))
}

func (o *bytesSockOpt) Get() []byte {
	return o.v
}

func (o *bytesSockOpt) SetSize(size int) BytesSockOpt {
	return o.Set(make([]byte, size))
}

func (o *bytesSockOpt) Set(v []byte) BytesSockOpt {
	o.v = v
	return o
}

func (o *bytesSockOpt) Marshal(b []byte) {
	if len(b) < len(o.v) {
		panic(fmt.Errorf("marshal to buffer of insufficient length: %d, want: %d",
			len(b), len(o.v)))
	}
	copy(b, o.v)
}

func (o *bytesSockOpt) Unmarshal(b []byte) {
	copy(o.v, b)
}

type StringSockOpt interface {
	RWSockOpt
	Get() string
	SetSize(int) StringSockOpt
	Set(string) StringSockOpt
}

type stringSockOpt struct {
	lvl int32
	typ int32
	v   string
}

func NewStringSockOpt(lvl, typ int32) StringSockOpt {
	return &stringSockOpt{
		lvl: lvl,
		typ: typ,
	}
}

func (o *stringSockOpt) Level() int32 {
	return o.lvl
}

func (o *stringSockOpt) Type() int32 {
	return o.typ
}

func (o *stringSockOpt) Len() uint64 {
	return uint64(len(o.v))
}

func (o *stringSockOpt) Get() string {
	return o.v
}

func (o *stringSockOpt) SetSize(size int) StringSockOpt {
	return o.Set(string(make([]byte, size)))
}

func (o *stringSockOpt) Set(v string) StringSockOpt {
	o.v = v
	return o
}

func (o *stringSockOpt) Marshal(b []byte) {
	if len(b) < len(o.v) {
		panic(fmt.Errorf("marshal to buffer of insufficient length: %d, want: %d",
			len(b), len(o.v)))
	}
	copy(b, o.v)
}

func (o *stringSockOpt) Unmarshal(b []byte) {
	o.v = string(b)
}
