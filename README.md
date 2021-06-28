# pingo [![Go Reference](https://pkg.go.dev/badge/github.com/mitinarseny/pingo.svg)](https://pkg.go.dev/github.com/mitinarseny/pingo) [![Go](https://github.com/mitinarseny/pingo/actions/workflows/go.yml/badge.svg)](https://github.com/mitinarseny/pingo/actions/workflows/go.yml)

Fast and lightweight ping library for Golang with multi-host support.

## Features

* [ICMP sockets](https://lwn.net/Articles/420800):  
  * UDP port 0 means "let the kernel pick a free number"
  * ICMP Echo Message ID is UDP port, so multiple instances of Pinger do not collide
* IPv4 and IPv6 support
* [TTL customization](https://pkg.go.dev/github.com/mitinarseny/pingo#Pinger.SetTTL)
* ICMP sequence numbers manager (no random): O(1) time, 256kB of memory
* [Context](https://pkg.go.dev/context) awareness

## Requirements

* go >= 1.16
* Linux kernel >= 3.11

You may need to adjust [`ping_group_range`](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)
sysfs to allow the creation of ICMP sockets:
```sh
$ echo 0 2147483647 > /proc/sys/net/ipv4/ping_group_range
```

## Example

```go
p, err := New(&net.UDPAddr{IP: net.IPv4zero}, nil)
if err != nil {
	fmt.Println(err)
	return
}

ctx, cancel := context.WithCancel(context.Background())
var g errgroup.Group
g.Go(func() error {
	return p.Listen(ctx, 100*time.Millisecond)
})

defer func() {
	cancel()
	if err := g.Wait(); !errors.Is(err, context.Canceled) {
		fmt.Println(err)
	}
}()

const send = 3
rtt, received, err := p.PingNContextInterval(ctx, net.IPv4(8, 8, 8, 8), send, 5*time.Second)
if err != nil {
	fmt.Println(err)
	return
}
fmt.Printf("packet loss: %f, avg RTT: %s", float32(send-received)/float32(send), rtt)
```

