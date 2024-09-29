package main

import (
	libseccomp "github.com/seccomp/libseccomp-golang"
)

type ProgramRunner struct {
	TimeLimit     uint64
	RealTimeLimit uint64
	MemoryLimit   uint64
	OutputLimit   uint64
	StackLimit    uint64

	InputFileName  string
	OutputFileName string
	ErrorFileName  string

	WorkPath string

	Args []string
	Env  []string

	Filter *libseccomp.ScmpFilter
}

func NewProgramRunner() ProgramRunner {
	return ProgramRunner{
		TimeLimit:     1,
		RealTimeLimit: 0,
		MemoryLimit:   256,
		OutputLimit:   64,
		StackLimit:    1024,
	}
}

func (r *ProgramRunner) verify() {
	if r.RealTimeLimit < r.TimeLimit {
		r.RealTimeLimit = r.TimeLimit + 2
	}
	if r.StackLimit > r.MemoryLimit {
		r.StackLimit = r.MemoryLimit
	}
}
