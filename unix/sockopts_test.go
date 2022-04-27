package unix

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestNewOption(t *testing.T) {
	const (
		lvl    = int32(1)
		typ    = int32(2)
		val    = int32(3)
		length = uint64(unsafe.Sizeof(val))
	)
	i := val
	o := NewSockOpt(lvl, typ, unsafe.Sizeof(i), unsafe.Pointer(&i))
	require.Equal(t, lvl, o.Level())
	require.Equal(t, typ, o.Type())
	require.Equal(t, length, o.Len())

	b := make([]byte, length)
	o.Marshal(b)

	want := make([]byte, length)
	*(*int32)(unsafe.Pointer(&want[0])) = i
	require.Equal(t, want, b)

	o.Unmarshal(want)
	require.Equal(t, val, i)
}
