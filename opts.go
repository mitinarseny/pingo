package ping

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type Option interface {
	Level() int32
	Type() int32
	Len() uint64
}

// ROption is a read getsockopt option
type ROption interface {
	Option
	Unmarshal([]byte)
}

// WOption is a write setsockopt option
type WOption interface {
	Option
	Marshal([]byte)
}

// RWOption is a read/write (get/set)sockopt option
type RWOption interface {
	ROption
	WOption
}

type opt struct {
	lvl    int32
	typ    int32
	length uintptr
	p      unsafe.Pointer
}

func NewOption(lvl, typ int32, length uintptr, p unsafe.Pointer) *opt {
	return &opt{
		lvl:    lvl,
		typ:    typ,
		length: length,
		p:      p,
	}
}

func (o *opt) Level() int32 {
	return o.lvl
}

func (o *opt) Type() int32 {
	return o.typ
}

func (o *opt) Len() uint64 {
	return uint64(o.length)
}

func (o *opt) Value() unsafe.Pointer {
	return o.p
}

func (o *opt) set(length uintptr, p unsafe.Pointer) {
	o.length = length
	o.p = p
}

func (o *opt) Marshal(b []byte) {
	if len(b) < int(o.length) {
		panic(fmt.Errorf("marshal to buffer of insufficient length: %d, want: %d",
			len(b), o.length))
	}
	copyP(unsafe.Pointer(&b[0]), o.p, o.length)
}

func (o *opt) Unmarshal(b []byte) {
	copyP(o.p, unsafe.Pointer(&b[0]), min(uintptr(len(b)), o.length))
}

func copyP(dst, src unsafe.Pointer, l uintptr) {
	var s uintptr
	for {
		if l >= unsafe.Sizeof(uint64(0)) {
			s = unsafe.Sizeof(uint64(0))
			*(*uint64)(dst) = *(*uint64)(src)
		} else if l >= unsafe.Sizeof(uint32(0)) {
			s = unsafe.Sizeof(uint32(0))
			*(*uint32)(dst) = *(*uint32)(src)
		} else if l >= unsafe.Sizeof(uint16(0)) {
			s = unsafe.Sizeof(uint16(0))
			*(*uint16)(dst) = *(*uint16)(src)
		} else if l >= unsafe.Sizeof(uint8(0)) {
			s = unsafe.Sizeof(uint8(0))
			*(*uint8)(dst) = *(*uint8)(src)
		} else {
			break
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

type BoolOption interface {
	RWOption
	Get() bool
	Set(bool) BoolOption
}

type boolOpt struct {
	*opt
}

func NewBoolOption(lvl, typ int32) BoolOption {
	return boolOpt{NewUint8Option(lvl, typ).(uint8Opt).opt}
}

func (o boolOpt) Get() bool {
	return uint8Opt{o.opt}.Get() != 0
}

func (o boolOpt) Set(v bool) BoolOption {
	var vv uint8
	if v {
		vv = 1
	}
	uint8Opt{o.opt}.Set(vv)
	return o
}

type Int8Option interface {
	RWOption
	Get() int8
	Set(int8) Int8Option
}

type int8Opt struct {
	*opt
}

func NewInt8Option(lvl, typ int32) Int8Option {
	v := new(int8)
	return int8Opt{NewOption(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o int8Opt) Get() int8 {
	return *(*int8)(o.Value())
}

func (o int8Opt) Set(v int8) Int8Option {
	*(*int8)(o.Value()) = v
	return o
}

type uint8Opt struct {
	*opt
}

type Uint8Option interface {
	RWOption
	Get() uint8
	Set(uint8) Uint8Option
}

func NewUint8Option(lvl, typ int32) Uint8Option {
	v := new(uint8)
	return uint8Opt{NewOption(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o uint8Opt) Get() uint8 {
	return *(*uint8)(o.Value())
}

func (o uint8Opt) Set(v uint8) Uint8Option {
	*(*uint8)(o.Value()) = v
	return o
}

type Int16Option interface {
	RWOption
	Get() int16
	Set(int16) Int16Option
}

type int16Opt struct {
	*opt
}

func NewInt16Option(lvl, typ int32) Int16Option {
	v := new(int16)
	return int16Opt{NewOption(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o int16Opt) Get() int16 {
	return *(*int16)(o.Value())
}

func (o int16Opt) Set(v int16) Int16Option {
	*(*int16)(o.Value()) = v
	return o
}

type Uint16Option interface {
	RWOption
	Get() uint16
	Set(uint16) Uint16Option
}

type uint16Opt struct {
	*opt
}

func NewUint16Option(lvl, typ int32) Uint16Option {
	v := new(uint16)
	return uint16Opt{NewOption(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o uint16Opt) Get() uint16 {
	return *(*uint16)(o.Value())
}

func (o uint16Opt) Set(v uint16) Uint16Option {
	*(*uint16)(o.Value()) = v
	return o
}

type Int32Option interface {
	RWOption
	Get() int32
	Set(int32) Int32Option
}

type int32Opt struct {
	*opt
}

func NewInt32Option(lvl, typ int32) Int32Option {
	v := new(int32)
	return int32Opt{NewOption(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o int32Opt) Get() int32 {
	return *(*int32)(o.Value())
}

func (o int32Opt) Set(v int32) Int32Option {
	*(*int32)(o.Value()) = v
	return o
}

type Uint32Option interface {
	RWOption
	Get() uint32
	Set(uint32) Uint32Option
}

type uint32Opt struct {
	*opt
}

func NewUint32Option(lvl, typ int32) Uint32Option {
	v := new(uint32)
	return uint32Opt{NewOption(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o uint32Opt) Get() uint32 {
	return *(*uint32)(o.Value())
}

func (o uint32Opt) Set(v uint32) Uint32Option {
	*(*uint32)(o.Value()) = v
	return o
}

type Int64Option interface {
	RWOption
	Get() int64
	Set(int64) Int64Option
}

type int64Opt struct {
	*opt
}

func NewInt64Option(lvl, typ int32) Int64Option {
	v := new(int64)
	return int64Opt{NewOption(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o int64Opt) Get() int64 {
	return *(*int64)(o.Value())
}

func (o int64Opt) Set(v int64) Int64Option {
	*(*int64)(o.Value()) = v
	return o
}

type Uint64Option interface {
	RWOption
	Get() uint64
	Set(uint64) Uint64Option
}

type uint64Opt struct {
	*opt
}

func NewUint64Option(lvl, typ int32) Uint64Option {
	v := new(uint64)
	return uint64Opt{NewOption(lvl, typ, unsafe.Sizeof(*v), unsafe.Pointer(v))}
}

func (o uint64Opt) Get() uint64 {
	return *(*uint64)(o.Value())
}

func (o uint64Opt) Set(v uint64) Uint64Option {
	*(*uint64)(o.Value()) = v
	return o
}

type bytesOpt struct {
	*opt
	v []byte
}

func NewBytesOption(lvl, typ int32, v []byte) *bytesOpt {
	return &bytesOpt{
		opt: NewOption(lvl, typ, uintptr(len(v)), unsafe.Pointer(&v[0])),
		v:   v,
	}
}

func (o *bytesOpt) Get() []byte {
	return o.v
}

func (o *bytesOpt) Set(v []byte) *bytesOpt {
	o.opt.set(uintptr(len(v)), unsafe.Pointer(&v[0]))
	o.v = v
	return o
}

// Set sets given options on the underlying socket with setsockopt(2)
func (p *Pinger) Set(opts ...WOption) error {
	var operr error
	if err := p.rc.Control(func(fd uintptr) {
		for _, o := range opts {
			b := make([]byte, o.Len())
			o.Marshal(b)
			if operr = unix.SetsockoptString(int(fd), int(o.Level()),
				int(o.Type()), string(b)); operr != nil {
				break
			}

		}
	}); err != nil {
		return err
	}
	return os.NewSyscallError("setsockopt", operr)
}

// Get gets given options from the underlying socket with getsockopt(2)
func (p *Pinger) Get(opts ...ROption) error {
	var operr error
	if err := p.rc.Control(func(fd uintptr) {
		for _, o := range opts {
			var s string
			s, operr = unix.GetsockoptString(int(fd), int(o.Level()), int(o.Type()))
			if operr != nil {
				break
			}
			o.Unmarshal([]byte(s))
		}
	}); err != nil {
		return err
	}
	return os.NewSyscallError("getsockopt", operr)
}

func marshalOpts(opts ...WOption) []byte {
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

func b2i(b bool) int32 {
	if b {
		return 1
	}
	return 0
}

func i2b(i int32) bool {
	return i != 0
}
