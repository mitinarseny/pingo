package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"runtime"
	"time"

	ping "github.com/mitinarseny/pingo"
	"golang.org/x/sync/errgroup"
)

var ttl = flag.Uint("t", 0, "TTL")
var timeout = flag.Duration("T", 0, "Timeout")
var mark = flag.Uint("m", 0, "Mark")
var laddr = flag.String("l", "", "Local addr to bind")
var nworkers = flag.Int("w", runtime.NumCPU(), "num workers")

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
		ip = net.ParseIP(args[0]).To4()
		if ip == nil {
			return fmt.Errorf("not an ip address: %s", args[0])
		}
	}
	var lladdr net.IP
	if *laddr != "" {
		lladdr = net.ParseIP(*laddr)
		if lladdr == nil {
			return fmt.Errorf("%q is not IP", *laddr)
		}
	}
	var nopts []ping.WOption
	if *ttl > 0 {
		nopts = append(nopts, ping.TTL(uint8(*ttl)))
	}
	p, err := ping.New(&net.UDPAddr{IP: lladdr}, nil, nopts...)
	if err != nil {
		return err
	}
	defer p.Close()
	tt := ping.TTL(0)
	mm := ping.Mark(0)
	if err := p.Get(tt, mm); err != nil {
		return err
	}
	fmt.Println("ttl:", tt.Get(), "mark:", mm.Get())
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
		err := p.Listen(ctx)
		fmt.Printf("listen exited: %s\n", err)
		return err
	})
	time.Sleep(1 * time.Second)

	g, ctx := errgroup.WithContext(ctx)

	var opts []ping.WOption
	if *ttl > 0 {
		// opts = append(opts, ping.TTL(uint8(*ttl)))
	}
	if *mark > 0 {
		opts = append(opts, ping.Mark(int32(*mark)))
	}

	chn := make(chan uint64)
	go func() {
		for i := uint64(0); i < math.MaxUint32+10; i++ {
			chn <- i
		}
		close(chn)
	}()

	ch := make(chan ping.Reply)
	go func() {
		last := uint64(1)
		cur := uint64(0)
		for r := range ch {
			cur++
			if cur < last*10 && cur < math.MaxUint32-10 {
				continue
			}
			last = cur
			fmt.Printf("%d: rtt: %s, ttl: %d, rerr: %s\n", cur, r.RTT, r.TTL, r.Err)
		}
	}()

	for i := 0; i < *nworkers; i++ {
		g.Go(func() error {
			for range chn {
				r, err := p.PingContext(ctx, ip, opts...)
				if err != nil {
					return err
				}
				ch <- r
			}
			return nil
		})
	}

	// ctx, cancel1 := context.WithTimeout(ctx, 3*time.Second)
	// defer cancel1()
	// last := uint64(1)
	// for i := uint64(0); i < math.MaxUint32+10; i++ {
	// 	i := i
	// 	// g.Go(func() error {
	// 	r, err := p.PingContextPayload(ctx, ip, []byte{0x01, 0x02}, opts...)
	// 	if i >= last*10 {
	// 		last = i
	// 		fmt.Printf("# %d\n", last)
	// 	}
	// 	if i > math.MaxUint32-10 {
	// 		fmt.Printf("%d: rtt: %s, ttl: %d, rerr: %s, err: %s\n", i, r.RTT, r.TTL, r.Err, err)
	// 	}
	// 	// return err
	// 	// })
	// }

	if err := g.Wait(); err != nil {
		return err
	}

	cancel()
	err = gl.Wait()
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
