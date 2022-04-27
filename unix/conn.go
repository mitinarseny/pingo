package unix

import (
	"context"
	"errors"
	"fmt"
	"os"
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

func (c *SocketConn) Accept() (nfd int, sa unix.Sockaddr, err error) {
	var operr error
	if err := c.Control(func(fd uintptr) {
		nfd, sa, operr = unix.Accept(int(fd))
	}); err != nil {
		return 0, nil, err
	}
	return nfd, sa, os.NewSyscallError("accept", operr)
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
			uintptr(unsafe.Pointer(&unix.RawSockaddrInet4{
				Family: unix.AF_UNSPEC,
			})), uintptr(unix.SizeofSockaddrInet4))
	}); err != nil {
		return err
	}
	return os.NewSyscallError("connect", operr)
}

func (c *SocketConn) SetSockOpts(opts ...WSockOpt) error {
	var operr error
	if err := c.Control(func(fd uintptr) {
		operr = SetSockOpts(fd, opts...)
	}); err != nil {
		return err
	}
	return operr
}

func (c *SocketConn) GetSockOpts(opts ...RSockOpt) error {
	var operr error
	if err := c.Control(func(fd uintptr) {
		operr = GetSockOpts(fd, opts...)
	}); err != nil {
		return err
	}
	return operr
}

func (c *SocketConn) BindToDevice(dev string) error {
	return c.SetSockOpts(
		NewStringSockOpt(unix.SOL_SOCKET, unix.SO_BINDTODEVICE).Set(dev))
}

func (c *SocketConn) BoundToDevice() (string, error) {
	o := NewStringSockOpt(unix.SOL_SOCKET, unix.SO_BINDTODEVICE).SetSize(unix.IFNAMSIZ)
	if err := c.GetSockOpts(o); err != nil {
		return "", err
	}
	return o.Get(), nil
}

func (c *SocketConn) BindToIfIndex(ifIndex int) error {
	return c.SetSockOpts(
		NewIntSockOpt(unix.SOL_SOCKET, unix.SO_BINDTODEVICE).Set(ifIndex))
}

func (c *SocketConn) BoundToIfIndex() (int, error) {
	o := NewIntSockOpt(unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX)
	if err := c.GetSockOpts(o); err != nil {
		return 0, err
	}
	return o.Get(), nil
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
		NewSockOpt(unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, unix.SizeofSockFprog,
			unsafe.Pointer(&unix.SockFprog{
				Len:    uint16(len(f)),
				Filter: (*unix.SockFilter)(unsafe.Pointer(&f[0])),
			})))
}

func errWouldBlock(err error) bool {
	return err == unix.EAGAIN || err == unix.EWOULDBLOCK
}

func (c *SocketConn) Read(f func(fd uintptr) (done bool)) error {
	return c.rc.Read(f)
}

func (c *SocketConn) RecvFrom(buf []byte, flags int) (n int, from unix.Sockaddr, err error) {
	var operr error
	if err := c.rc.Read(func(fd uintptr) (done bool) {
		n, from, operr = unix.Recvfrom(int(fd), buf, flags)
		return !errWouldBlock(operr)
	}); err != nil {
		return 0, nil, err
	}
	return n, from, os.NewSyscallError("recvfrom", operr)
}

func (c *SocketConn) RecvMsg(buf []byte, oob []byte, flags int) (n, oobn int, recvflags int, from unix.Sockaddr, err error) {
	var operr error
	if err := c.rc.Read(func(fd uintptr) (done bool) {
		n, oobn, recvflags, from, operr = unix.Recvmsg(int(fd), buf, oob, flags)
		return !errWouldBlock(operr)
	}); err != nil {
		return 0, 0, 0, nil, err
	}
	return n, oobn, recvflags, from, os.NewSyscallError("recvmsg", operr)
}

func (c *SocketConn) RecvMmsg(hs []Mmsghdr, flags int) (n int, err error) {
	var operr error
	if err := c.rc.Read(func(fd uintptr) (done bool) {
		n, operr = Recvmmsg(fd, hs, flags)
		return !errWouldBlock(operr)
	}); err != nil {
		return 0, err
	}
	return n, os.NewSyscallError("recvmmsg", operr)
}

func (c *SocketConn) Write(f func(fd uintptr) (done bool)) error {
	return c.rc.Write(f)
}

func (c *SocketConn) SendTo(buf []byte, flags int, to unix.Sockaddr) error {
	var operr error
	if err := c.rc.Write(func(fd uintptr) (done bool) {
		operr = unix.Sendto(int(fd), buf, flags, to)
		return !errWouldBlock(operr)
	}); err != nil {
		return err
	}
	return os.NewSyscallError("sendto", operr)
}

func (c *SocketConn) SendMsg(buf []byte, to unix.Sockaddr, flags int, opts ...WSockOpt) (n int, err error) {
	oob := MarshalCmsg(opts...)
	var operr error
	if err := c.rc.Write(func(fd uintptr) (done bool) {
		n, operr = unix.SendmsgN(int(fd), buf, oob, to, flags)
		return !errWouldBlock(operr)
	}); err != nil {
		return 0, err
	}
	return n, os.NewSyscallError("sendmsg", operr)
}

func (c *SocketConn) SendMmsg(hs []Mmsghdr, flags int) (n int, err error) {
	var operr error
	if err := c.rc.Write(func(fd uintptr) (done bool) {
		n, operr = Sendmmsg(fd, hs, flags)
		return !errWouldBlock(operr)
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

func (c *SocketConn) setContext(m mode, ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if err := c.unlock(m); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = c.lock(m)
	}()
	return ctx.Err()
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

func (c *SocketConn) SetContext(ctx context.Context) error {
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

func (c *SocketConn) SetReadContext(ctx context.Context) error {
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

func (c *SocketConn) SetWriteContext(ctx context.Context) error {
	return c.setContext(w, ctx)
}
