package unix

import "golang.org/x/sys/unix"

func errnoErr(e unix.Errno) error {
	if e == 0 {
		return nil
	}
	return e
}
