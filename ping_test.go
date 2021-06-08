package ping

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

var ipv4Loopback = net.IPv4(127, 0, 0, 1)

func TestPinger(t *testing.T) {
	p, err := New(&net.UDPAddr{IP: ipv4Loopback}, ipv4Loopback)
	require.NoError(t, err)
	defer p.Close()

	_, err = p.SetTTL(1)
	require.NoError(t, err)
	ttl, err := p.SetTTL(0)
	require.NoError(t, err)
	require.EqualValues(t, 1, ttl)

	ctx, cancel := context.WithCancel(context.Background())

	var g errgroup.Group
	g.Go(func() error {
		return p.Listen(ctx, 100*time.Millisecond)
	})

	t.Run("PingContext", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			t.Run(strconv.Itoa(i), func(t *testing.T) {
				t.Parallel()
				rtt, err := p.PingContext(ctx, ipv4Loopback)
				require.NoError(t, err)
				require.NotZero(t, rtt)
			})
		}
	})
	cancel()
	require.Equal(t, context.Canceled, g.Wait())
}

func BenchmarkPinger(b *testing.B) {
	p, err := New(&net.UDPAddr{IP: ipv4Loopback}, ipv4Loopback)
	if err != nil {
		b.Fatal(err)
	}
	defer p.Close()
	if _, err := p.SetTTL(1); err != nil {
		b.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go p.Listen(ctx, 100*time.Millisecond)

	var sumRTT time.Duration

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var sum time.Duration
		for pb.Next() {
			rtt, err := p.PingContext(ctx, ipv4Loopback)
			if err != nil {
				b.Fatal(err)
			}
			sum += rtt
		}
		atomic.AddInt64((*int64)(&sumRTT), int64(sum))
	})

	avgRtt := sumRTT / time.Duration(b.N)
	b.ReportMetric(float64(avgRtt.Microseconds()), "rtt(μs)/op")
}

func ExamplePinger_PingContextTimeout() {
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
}
