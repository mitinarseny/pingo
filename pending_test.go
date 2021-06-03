package ping

import (
	"context"
	"testing"
	"time"
)

func BenchmarkPendingSeqs(b *testing.B) {
	p := newSequences()
	ctx := context.Background()
	b.SetParallelism(100)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			seq, _, err := p.add(ctx, nil, time.Time{})
			if err != nil {
				b.Fatal(err)
			}
			p.get(seq)
			p.free(seq)
		}
	})
}
