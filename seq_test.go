package ping

import (
	"context"
	"testing"
)

func BenchmarkSequences(b *testing.B) {
	p := newSequences()
	ctx := context.Background()
	b.SetParallelism(100)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			seq, _, err := p.add(ctx, nil)
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
