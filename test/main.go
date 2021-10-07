package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	ping "github.com/mitinarseny/pingo"
	"golang.org/x/sync/errgroup"
)

var ttl = flag.Uint("t", 64, "TTL")
var timeout = flag.Duration("T", 0, "Timeout")
var mark = flag.Uint("m", 0, "Mark")

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
	time.Sleep(0)
	ip := net.IPv4(127, 0, 0, 1).To4()
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
	var tt ping.TTL
	var mm ping.Mark
	if err := p.Get(&tt, &mm); err != nil {
		return err
	}
	fmt.Println("ttl:", tt, "mark:", mm)
	//
	// if *ttl > 0 {
	// 	if err := p.SetTTL(uint8(*ttl)); err != nil {
	// 		return fmt.Errorf("set ttl: %w", err)
	// 	}
	// }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var gl errgroup.Group
	gl.Go(func() error {
		err := p.Listen(ctx, 10, 1500)
		fmt.Printf("listen err: %s\n", err)
		return err
	})

	g, ctx := errgroup.WithContext(ctx)

	opts := []ping.SetOption{ping.TTL(uint8(*ttl))}
	if *mark > 0 {
		opts = append(opts, ping.Mark(*mark))
	}

	for i := 0; i < 100; i++ {
		i := i
		g.Go(func() error {
			r, err := p.PingContext(ctx, ip)
			fmt.Printf("%d rtt: %s, rerr: %s, ttl: %d, err: %s\n", i, r.RTT, r.Err, r.TTL, err)
			return err
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	cancel()
	return gl.Wait()
}
