package ping

import (
	"fmt"
	"net"
)

var icmpError ICMPError

type ICMPError interface {
	error
	From() net.IP
}

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
	from net.IP
	code DstUnreachableCode
}

func NewDestinationUnreachableError(from net.IP, code DstUnreachableCode) error {
	return DestinationUnreachableError{
		from: from,
		code: code,
	}
}

func (e DestinationUnreachableError) Error() string {
	return fmt.Sprintf("from %s: %s", e.From(), e.code.Error())
}

func (e DestinationUnreachableError) From() net.IP {
	return e.from
}

func (e DestinationUnreachableError) Unwrap() error {
	return e.code
}

type TimeExceededError net.IP

func NewTimeExceededError(from net.IP) error {
	return TimeExceededError(from)
}

func (e TimeExceededError) Error() string {
	return fmt.Sprintf("from %s: TTL exceeded in transit", e.From())
}

func (e TimeExceededError) From() net.IP {
	return net.IP(e)
}
