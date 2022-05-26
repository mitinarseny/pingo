package unix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

type SocketConn struct {
	f  *os.File
	rc syscall.RawConn
}

func NewSocketConn(domain, typ, proto int) (*SocketConn, error) {
	s, err := unix.Socket(domain, typ|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, proto)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	f := os.NewFile(uintptr(s), "socket connection")
	if f == nil {
		_ = unix.Close(s)
		return nil, errors.New("invalid file descriptor")
	}
	rc, err := f.SyscallConn()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &SocketConn{
		f:  f,
		rc: rc,
	}, nil
}

func (c *SocketConn) Close() error {
	return c.f.Close()
}

func (c *SocketConn) Control(f func(fd uintptr)) error {
	return c.rc.Control(f)
}

func (c *SocketConn) Bind(sa unix.Sockaddr) error {
	var operr error
	if err := c.Control(func(fd uintptr) {
		operr = unix.Bind(int(fd), sa)
	}); err != nil {
		return err
	}
	return os.NewSyscallError("bind", operr)
}

func (c *SocketConn) Listen(backlog int) error {
	var operr error
	if err := c.Control(func(fd uintptr) {
		operr = unix.Listen(int(fd), backlog)
	}); err != nil {
		return err
	}
	return os.NewSyscallError("listen", operr)
}

func (c *SocketConn) Connect(sa unix.Sockaddr) error {
	var operr error
	if err := c.Control(func(fd uintptr) {
		operr = unix.Connect(int(fd), sa)
	}); err != nil {
		return err
	}
	return os.NewSyscallError("connect", operr)
}

func (c *SocketConn) Disconnect() error {
	var operr error
	if err := c.Control(func(fd uintptr) {
		_, _, operr = unix.Syscall(unix.SYS_CONNECT, fd,
			uintptr(unsafe.Pointer(&unix.RawSockaddr{
				Family: unix.AF_UNSPEC,
			})), unsafe.Sizeof(unix.RawSockaddr{}))
	}); err != nil {
		return err
	}
	return os.NewSyscallError("connect", operr)
}

func (c *SocketConn) SetSockOpts(opts ...SockOpt) error {
	var operr error
	if err := c.Control(func(fd uintptr) {
		operr = SetSockOpts(fd, opts...)
	}); err != nil {
		return err
	}
	return operr
}

func (c *SocketConn) GetSockOpts(opts ...SockOpt) error {
	var operr error
	if err := c.Control(func(fd uintptr) {
		operr = GetSockOpts(fd, opts...)
	}); err != nil {
		return err
	}
	return operr
}

func (c *SocketConn) Domain() (int, error) {
	o := NewSockOpt[int](unix.SOL_SOCKET, unix.SO_DOMAIN)
	err := c.GetSockOpts(o)
	return o.Get(), err
}

func (c *SocketConn) Type() (int, error) {
	o := NewSockOpt[int](unix.SOL_SOCKET, unix.SO_TYPE)
	err := c.GetSockOpts(o)
	return o.Get(), err
}

func (c *SocketConn) Proto() (int, error) {
	o := NewSockOpt[int](unix.SOL_SOCKET, unix.SO_PROTOCOL)
	err := c.GetSockOpts(o)
	return o.Get(), err
}

func (c *SocketConn) BindToDevice(dev string) error {
	return c.SetSockOpts(
		NewBytesSockOpt[string](unix.SOL_SOCKET, unix.SO_BINDTODEVICE).Set(dev))
}

func (c *SocketConn) BoundToDevice() (string, error) {
	o := NewBytesSockOpt[string](unix.SOL_SOCKET, unix.SO_BINDTODEVICE).SetSize(unix.IFNAMSIZ)
	err := c.GetSockOpts(o)
	return o.Get(), err
}

func (c *SocketConn) BindToIfIndex(ifIndex int) error {
	return c.SetSockOpts(NewSockOpt[int](unix.SOL_SOCKET, unix.SO_BINDTODEVICE).Set(ifIndex))
}

func (c *SocketConn) BoundToIfIndex() (int, error) {
	o := NewSockOpt[int](unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX)
	err := c.GetSockOpts(o)
	return o.Get(), err
}

func (c *SocketConn) AttachFilter(instrs []bpf.Instruction) error {
	f, err := bpf.Assemble(instrs)
	if err != nil {
		return fmt.Errorf("BPF assemble: %w", err)
	}
	return c.AttachFilterRaw(f)
}

func (c *SocketConn) AttachFilterRaw(f []bpf.RawInstruction) error {
	return c.SetSockOpts(
		NewSockOpt[unix.SockFprog](unix.SOL_SOCKET, unix.SO_ATTACH_FILTER).Set(
			unix.SockFprog{
				Len:    uint16(len(f)),
				Filter: (*unix.SockFilter)(unsafe.Pointer(&f[0])),
			}))
}

func (c *SocketConn) Read(f func(fd uintptr) (done bool)) error {
	return c.rc.Read(f)
}

func (c *SocketConn) Accept() (nfd int, sa unix.Sockaddr, err error) {
	var operr error
	if err := c.Read(func(fd uintptr) (done bool) {
		nfd, sa, operr = unix.Accept(int(fd))
		return !isTemporary(operr)
	}); err != nil {
		return 0, nil, err
	}
	return nfd, sa, os.NewSyscallError("accept", operr)
}

func (c *SocketConn) RecvFrom(buf []byte, flags int) (n int, from unix.Sockaddr, err error) {
	var operr error
	if err := c.rc.Read(func(fd uintptr) (done bool) {
		n, from, operr = unix.Recvfrom(int(fd), buf, flags|unix.MSG_DONTWAIT)
		return !isTemporary(operr)
	}); err != nil {
		return 0, nil, err
	}
	return n, from, os.NewSyscallError("recvfrom", operr)
}

func (c *SocketConn) RecvMsg(buf []byte, oob []byte, flags int) (n, oobn int, recvflags int, from unix.Sockaddr, err error) {
	var operr error
	if err := c.rc.Read(func(fd uintptr) (done bool) {
		n, oobn, recvflags, from, operr = unix.Recvmsg(int(fd), buf, oob, flags|unix.MSG_DONTWAIT)
		return !isTemporary(operr)
	}); err != nil {
		return 0, 0, 0, nil, err
	}
	return n, oobn, recvflags, from, os.NewSyscallError("recvmsg", operr)
}

func (c *SocketConn) RecvMmsg(hs []Mmsghdr, flags int) (n int, err error) {
	var operr error
	if err := c.rc.Read(func(fd uintptr) (done bool) {
		n, operr = Recvmmsg(fd, hs, flags|unix.MSG_DONTWAIT)
		return !isTemporary(operr)
	}); err != nil {
		return 0, err
	}
	return n, os.NewSyscallError("recvmmsg", operr)
}

type SockMsg struct {
	From    []byte
	Data    []byte
	Control []byte
	Flags   int32
}

func (c *SocketConn) ListenPacket(ctx context.Context, flags int,
	numMsgs, dataLen, controlLen int, handler func(SockMsg) error) error {
	if handler == nil {
		panic("nil handler")
	}

	cancel, err := c.SetReadContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	domain, err := c.Domain()
	if err != nil {
		return err
	}
	sas, buffs, oobs, hs := MakeMmsghdrs(domain,
		numMsgs, dataLen, controlLen)

	for {
		n, err := c.RecvMmsg(hs, flags)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return ctx.Err()
			}
			return err
		}
		for i := range hs[:n] {
			if err := handler(SockMsg{
				From:    sas[i][:hs[i].Hdr.Namelen],
				Data:    buffs[i][:hs[i].Len],
				Control: oobs[i][:hs[i].Hdr.Controllen],
				Flags:   hs[i].Hdr.Flags,
			}); err != nil {
				return err
			}
			// we need to reset control length to original oob length
			// and namelen since it was changed by recvmmsg(2).
			hs[i].Hdr.Namelen = SockaddrLen(domain)
			hs[i].Hdr.SetControllen(len(oobs[i]))
		}
	}
}

func (c *SocketConn) Write(f func(fd uintptr) (done bool)) error {
	return c.rc.Write(f)
}

func (c *SocketConn) SendTo(buf []byte, flags int, to unix.Sockaddr) error {
	var operr error
	if err := c.rc.Write(func(fd uintptr) (done bool) {
		operr = unix.Sendto(int(fd), buf, flags|unix.MSG_DONTWAIT, to)
		return !isTemporary(operr)
	}); err != nil {
		return err
	}
	return os.NewSyscallError("sendto", operr)
}

func (c *SocketConn) SendMsg(buf []byte, to unix.Sockaddr, flags int, opts ...SockOpt) (n int, err error) {
	oob := MarshalCmsg(opts...)
	var operr error
	if err := c.rc.Write(func(fd uintptr) (done bool) {
		n, operr = unix.SendmsgN(int(fd), buf, oob, to, flags|unix.MSG_DONTWAIT)
		return !isTemporary(operr)
	}); err != nil {
		return 0, err
	}
	return n, os.NewSyscallError("sendmsg", operr)
}

func (c *SocketConn) SendMmsg(hs []Mmsghdr, flags int) (n int, err error) {
	var operr error
	if err := c.rc.Write(func(fd uintptr) (done bool) {
		n, operr = Sendmmsg(fd, hs, flags|unix.MSG_DONTWAIT)
		return !isTemporary(operr)
	}); err != nil {
		return 0, err
	}
	return n, os.NewSyscallError("sendmmsg", operr)
}

type mode uint8

const (
	r mode = iota
	w
	rw
)

func (c *SocketConn) setDeadline(m mode, t time.Time) error {
	switch m {
	case r:
		return c.SetReadDeadline(t)
	case w:
		return c.SetWriteDeadline(t)
	case rw:
		return c.SetDeadline(t)
	}
	panic(fmt.Errorf("unknown mode: %d", m))
}

func (c *SocketConn) lock(m mode) error {
	return c.setDeadline(m, time.Now())
}

func (c *SocketConn) unlock(m mode) error {
	return c.setDeadline(m, time.Time{})
}

func (c *SocketConn) setContext(m mode, ctx context.Context) (context.CancelFunc, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if err := c.unlock(m); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		_ = c.lock(m)
	}()

	return func() {
		cancel()
		wg.Wait()
	}, nil
}

func (c *SocketConn) SetDeadline(t time.Time) error {
	return c.f.SetDeadline(t)
}

func (c *SocketConn) Lock() error {
	return c.lock(rw)
}

func (c *SocketConn) Unlock() error {
	return c.unlock(rw)
}

func (c *SocketConn) SetContext(ctx context.Context) (context.CancelFunc, error) {
	return c.setContext(rw, ctx)
}

func (c *SocketConn) SetReadDeadline(t time.Time) error {
	return c.f.SetReadDeadline(t)
}

func (c *SocketConn) RLock() error {
	return c.SetReadDeadline(time.Now())
}

func (c *SocketConn) RUnlock() error {
	return c.SetReadDeadline(time.Time{})
}

func (c *SocketConn) SetReadContext(ctx context.Context) (context.CancelFunc, error) {
	return c.setContext(r, ctx)
}

func (c *SocketConn) SetWriteDeadline(t time.Time) error {
	return c.f.SetWriteDeadline(t)
}

func (c *SocketConn) WLock() error {
	return c.SetWriteDeadline(time.Now())
}

func (c *SocketConn) WUnlock() error {
	return c.SetWriteDeadline(time.Time{})
}

func (c *SocketConn) SetWriteContext(ctx context.Context) (context.CancelFunc, error) {
	return c.setContext(w, ctx)
}

func isTemporary(err error) bool {
	t, ok := err.(unix.Errno)
	return ok && t.Temporary()
}
