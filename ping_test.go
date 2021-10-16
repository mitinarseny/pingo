package ping

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"sync/atomic"
	"time"
	"unsafe"

	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

var ipv4Loopback = net.IPv4(127, 0, 0, 1)

func TestPinger(t *testing.T) {
	p, err := New(&net.UDPAddr{IP: ipv4Loopback}, TTL(1))
	require.NoError(t, err)
	defer p.Close()

	ttl := TTL(0)
	require.NoError(t, p.Get(ttl))
	require.EqualValues(t, 1, ttl.Get())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	var g errgroup.Group
	g.Go(func() error {
		return p.Listen(ctx)
	})
	defer func() {
		cancel()
		require.Equal(t, context.Canceled, g.Wait())
	}()

	t.Run("PingContext", func(t *testing.T) {
		for i := uint16(0); i < 100; i++ {
			i := i
			t.Run(strconv.FormatUint(uint64(i), 10), func(t *testing.T) {
				t.Parallel()
				b := make([]byte, unsafe.Sizeof(i))
				*(*uint16)(unsafe.Pointer(&b[0])) = i
				r, err := p.PingContextPayload(ctx, ipv4Loopback, b, ttl)
				require.NoError(t, err)
				require.NoError(t, r.Err)
				require.NotZero(t, r.RTT)
				require.Equal(t, b, r.Data)
			})
		}
	})
}

func BenchmarkPinger(b *testing.B) {
	p, err := New(&net.UDPAddr{IP: ipv4Loopback}, TTL(1))
	if err != nil {
		b.Fatal(err)
	}
	defer p.Close()

	ctx, cancel := context.WithCancel(context.Background())
	var g errgroup.Group
	g.Go(func() error {
		return p.Listen(ctx)
	})
	defer func(){
		cancel()
		if err := g.Wait(); !errors.Is(err, context.Canceled) {
			b.Fatal(err)
		}
	}()
	var sumRTT time.Duration
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var sum time.Duration
		for pb.Next() {
			r, err := p.PingContext(ctx, ipv4Loopback)
			if err != nil {
				b.Fatal(err)
			}
			if r.Err != nil {
				b.Fatal(err)
			}
			sum += r.RTT
		}
		atomic.AddInt64((*int64)(&sumRTT), int64(sum))
	})

	avgRtt := sumRTT / time.Duration(b.N)
	b.ReportMetric(float64(avgRtt.Microseconds()), "rtt(μs)/op")
}

func Example_traceroute() {
	dst := net.IPv4(8, 8, 8, 8)

	p, err := New(nil)
	if err != nil {
		fmt.Println(err)
		return
	}

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
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				// no answer from current hop
				fmt.Println("...")
				continue
			}
			fmt.Println(err)
			return
		}
		from := dst
		if r.Err != nil {
			from = r.Err.From()
		}
		fmt.Printf("%-15s %s\n", from, r.RTT)
		switch r.Err.(type) {
		case TimeExceededError:
			continue
		case nil:
			return
		default:
			fmt.Println(err)
			return
		}
	}
	fmt.Println("TTL maxed out")
}

func ExamplePinger_PingContextPayload() {
	p, err := New(nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	var g errgroup.Group
	g.Go(func() error {
		return p.Listen(ctx)
	})
	defer func() {
		cancel()
		if err := g.Wait(); !errors.Is(err, context.DeadlineExceeded) &&
			!errors.Is(err, context.Canceled) {
			fmt.Println(err)
		}
	}()

	payload := "HELLO, ARE YOU THERE?"
	r, err := p.PingContextPayload(ctx, net.IPv4(8, 8, 8, 8), []byte(payload))
	if err != nil {
		fmt.Println(err)
		return
	}
	if r.Err != nil {
		fmt.Printf("RTT: %s, TTL: %d, ICMP error: %s\n", r.RTT, r.TTL, r.Err)
		return
	}
	fmt.Printf("RTT: %s, TTL: %d, payload: %s\n", r.RTT, r.TTL, string(r.Data))
}

func ExamplePinger_PingNContextInterval() {
	p, err := New(nil)
	if err != nil {
		fmt.Println(err)
		return
	}

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

	const send = 3
	rs, err := p.PingNContextInterval(ctx, net.IPv4(8, 8, 8, 8), send, 1*time.Second)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("packet loss: %f, avg RTT: %s\n", float32(send-len(rs))/float32(send), rs.AvgRTT())
}
