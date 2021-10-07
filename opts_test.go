package ping

import (
	"fmt"
	"log"
)

func ExamplePinger_Set() {
	p, _ := New(nil, nil)
	if err := p.Set(TTL(1)); err != nil {
		log.Panic(err)
	}
}

func ExamplePinger_Get() {
	p, _ := New(nil, nil)
	var ttl TTL
	if err := p.Get(&ttl); err != nil {
		log.Panic(err)
	}
	fmt.Println(ttl)
}
