# pingo [![Go Reference](https://pkg.go.dev/badge/github.com/mitinarseny/pingo.svg)](https://pkg.go.dev/github.com/mitinarseny/pingo)

Golang ping library

## Features

* ICMP sockets (TODO: link to linux kernel docs on ICMP sockets)
  TODO: exmplain benefits: auto picking, no receive not ours packets and no collisions
  TODO: /proc param
* IPv4 and IPv6 support
* TTL customization
* No random at picking an ICMP sequence numbers
  TODO: explain how they are managed and provide info about memory usage
* [context](https://pkg.go.dev/context) awareness

## Requirements

* Linux >= TODO
* go >= 1.16 (TODO?)

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

