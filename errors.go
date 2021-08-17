package ping

import (
	"fmt"
	"net"
)

type DstUnreachableCode uint8

const (
	NetUnreachable DstUnreachableCode = iota
	HostUnreachable
	ProtocolUnreachable
	PortUnreachable
	FragmentationNeeded
	SourceRouteFailed
)

func (c DstUnreachableCode) Error() string {
	switch c {
	case NetUnreachable:
		return "net unreachable"
	case HostUnreachable:
		return "host unreachable"
	case ProtocolUnreachable:
		return "protocol unreachable"
	case PortUnreachable:
		return "port unreachable"
	case FragmentationNeeded:
		return "fragmentation needed and DF set"
	case SourceRouteFailed:
		return "source route failed"
	default:
		return "unknown error"
	}
}

type DestinationUnreachableError struct {
	From *net.IPAddr
	Code DstUnreachableCode
}

func (e DestinationUnreachableError) Error() string {
	return fmt.Sprintf("from %s: %s", e.From, e.Code.Error())
}

func (e DestinationUnreachableError) Unwrap() error {
	return e.Code
}

type TimeExceeded struct {
	From *net.IPAddr
}

func (e TimeExceeded) Error() string {
	return fmt.Sprintf("from %s: TTL exceeded in transit", e.From)
}
