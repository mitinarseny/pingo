package ping

import (
	"context"
	"encoding/binary"
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

	ttl := TTL(1)
	require.NoError(t, p.Set(ttl))
	require.NoError(t, p.Get(&ttl))
	require.EqualValues(t, 1, ttl)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	var g errgroup.Group
	g.Go(func() error {
		return p.Listen(ctx, 100, 200)
	})

	// wait for listen to start
	time.Sleep(1 * time.Second)

	t.Run("PingContext", func(t *testing.T) {
		for i := uint16(0); i < 100; i++ {
			i := i
			t.Run(strconv.FormatUint(uint64(i), 10), func(t *testing.T) {
				// t.Parallel()
				b := make([]byte, 2)
				binary.BigEndian.PutUint16(b, i)
				r, err := p.PingContextPayload(ctx, ipv4Loopback, b)
				require.NoError(t, err)
				require.NoError(t, r.Err)
				require.NotZero(t, r.RTT)
				require.Equal(t, b, r.Data)
			})
		}
	})
	t.Log("all exited")
	cancel()
	require.Equal(t, context.Canceled, g.Wait())
}

func BenchmarkPinger(b *testing.B) {
	p, err := New(&net.UDPAddr{IP: ipv4Loopback}, ipv4Loopback)
	if err != nil {
		b.Fatal(err)
	}
	defer p.Close()
	if err := p.Set(TTL(1)); err != nil {
		b.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// TODO: msgBuffSize
	go p.Listen(ctx, 10, 0)

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

func ExamplePinger_PingNContextInterval() {
	p, err := New(&net.UDPAddr{IP: net.IPv4zero}, nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	var g errgroup.Group
	g.Go(func() error {
		return p.Listen(ctx, 10, 0)
	})

	defer func() {
		cancel()
		if err := g.Wait(); !errors.Is(err, context.Canceled) {
			fmt.Println(err)
		}
	}()

	const send = 3
	rs, err := p.PingNContextInterval(ctx, net.IPv4(8, 8, 8, 8), send, 5*time.Second)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("packet loss: %f, avg RTT: %s\n", float32(send-len(rs))/float32(send), rs.AvgRTT())
}
