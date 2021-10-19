# pingo [![Go Reference](https://pkg.go.dev/badge/github.com/mitinarseny/pingo.svg)](https://pkg.go.dev/github.com/mitinarseny/pingo) [![Go](https://github.com/mitinarseny/pingo/actions/workflows/go.yml/badge.svg)](https://github.com/mitinarseny/pingo/actions/workflows/go.yml)

Fast and lightweight ping library for Golang with multi-host support.

## Features

* [ICMP sockets](https://lwn.net/Articles/420800):
  * UDP port 0 means "let the kernel pick a free number"
  * ICMP Echo Message ID is UDP port, so multiple instances of Pinger do not collide
* Support for custom [setsockopt(2)](https://man7.org/linux/man-pages/man2/getsockopt.2.html)
  and [sendmsg(2)](https://man7.org/linux/man-pages/man2/sendmsg.2.html) options
* Support for Linux kernel RX and TX timestamps with
  [SO_TIMESTAMPING](https://www.kernel.org/doc/Documentation/networking/timestamping.txt)
* IPv4 and IPv6 support
* ICMP sequence numbers manager (no random): O(1) time, 256kB of memory
* [Context](https://pkg.go.dev/context) awareness

## Requirements

* go >= 1.16
* Linux kernel >= 3.11

You may need to adjust
[`ping_group_range`](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)
sysfs to allow the creation of ICMP sockets:
```sh
$ echo 0 2147483647 > /proc/sys/net/ipv4/ping_group_range
```

## Example

Here is a simple [traceroute(8)](https://man7.org/linux/man-pages/man8/traceroute.8.html)
implementation:

```go
dst := net.IPv4(8, 8, 8, 8)

p, err := New(nil)
if err != nil {
	fmt.Println(err)
	return
}
defer p.Close()

ctx, cancel := context.WithCancel(context.Background())
var g errgroup.Group
g.Go(func() error {
	return p.Listen(ctx)
})
defer func() {
	cancel()
	if err := g.Wait(); !errors.Is(err, context.Canceled) {
		fmt.Println(err)
	}
}()

for ttl := uint8(1); ttl < math.MaxUint8-1; ttl++ {
	fmt.Printf("%3d: ", ttl)
	r, err := p.PingContextTimeout(ctx, dst, 1*time.Second, TTL(ttl))
	if errors.Is(err, context.DeadlineExceeded) {
		// no answer from current hop
		fmt.Println("...")
		continue
	}
	from := dst
	switch err := err.(type) {
	case nil:
	case TimeExceededError:
		from = err.From()
	default:
		fmt.Println(err)
		return
	}
	fmt.Printf("%-15s %s\n", from, r.RTT)
	if err == nil {
		return
	}
}
fmt.Println("TTL maxed out")
```

