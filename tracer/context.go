package tracer

import "syscall"

type Context struct {
	pid int

	regs syscall.PtraceRegs
}

func clen(b []byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			return i
		}
	}
	return len(b) + 1
}

func getTrapContext(pid int) (*Context, error) {
	var regs syscall.PtraceRegs
	err := syscall.PtraceGetRegs(pid, &regs)
	if err != nil {
		return nil, err
	}
	return &Context{
		pid:  pid,
		regs: regs,
	}, nil
}
