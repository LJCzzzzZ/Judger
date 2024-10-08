package tracee

import (
	"io/ioutil"
	"os"
	"syscall"
	"unsafe"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

func FilterToBPF(filter *libseccomp.ScmpFilter) (*syscall.SockFprog, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	go func() {
		filter.ExportBPF(w)
		filter.Release()
		w.Close()
	}()

	bin, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return &syscall.SockFprog{
		Len:    uint16(len(bin) / 8),
		Filter: (*syscall.SockFilter)(unsafe.Pointer(&bin[0])),
	}, nil
}
