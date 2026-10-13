//go:build embedbpf

package main

// Single-binary build (paper Section 6.8). Compile the data plane first, then:
//     clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c zerocall.bpf.c -o zerocall.bpf.o
//     go build -tags embedbpf -o zerocall .
// The resulting binary carries the eBPF bytecode and needs no .o on the target.

import _ "embed"

//go:embed zerocall.bpf.o
var embeddedBPF []byte

func init() { bpfObject = embeddedBPF }
