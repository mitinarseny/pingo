package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"

	ping "github.com/mitinarseny/pingo"
	"golang.org/x/sync/errgroup"
)

var ttl = flag.Uint("t", 0, "TTL")

func main() {
	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "flag: %s\n", err)
	}
	if err := run(flag.Args()); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	ip := net.IPv4(127, 0, 0, 1)
	if len(args) == 1 {
		ip = net.ParseIP(args[0])
		if ip == nil {
			return fmt.Errorf("not an ip address: %s", args[0])
		}
	}
	p, err := ping.New(nil, nil)
	if err != nil {
		return err
	}
	defer p.Close()

	if *ttl > 0 {
		if err := p.SetTTL(uint8(*ttl)); err != nil {
			return fmt.Errorf("set ttl: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()


	var g errgroup.Group
	g.Go(func() error {
		err := p.Listen(ctx, 10, 1500)
		fmt.Printf("listen err: %s\n", err)
		return err
	})
	for i := 0; i < 10; i++ {
		// time.Sleep(100*time.Millisecond)
		rtt, err := p.PingContext(ctx, ip)
			fmt.Printf("%d rtt: %s, err: %s\n", i, rtt, err)
	}

	cancel()
	return g.Wait()
}
