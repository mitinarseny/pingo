package ping

import (
	"context"
	"math"
	"testing"
)

func BenchmarkReserve(b *testing.B) {
	r := newReserve()
	ctx := context.Background()
	b.SetParallelism(2*math.MaxUint16)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			seq, err := r.get(ctx)
			if err != nil {
				b.Fatal(err)
			}
			r.free(seq)
		}
	})
}

func BenchmarkSequences(b *testing.B) {
	p := newSequences()
	ctx := context.Background()
	b.SetParallelism(2 * math.MaxUint16)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			seq, _, err := p.add(ctx)
			if err != nil {
				b.Fatal(err)
			}
			if p.get(seq) == nil {
				b.Fatal("nil pend")
			}
			p.free(seq)
		}
	})
}
