package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	log.Println("Starting ZeroCall-eBPF Control Plane...")

	// 1. Load the compiled eBPF object file from the disk
	spec, err := ebpf.LoadCollectionSpec("zerocall.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF object: %v", err)
	}

	// 2. Define structures to hold our loaded kernel objects
	objs := struct {
		ZeroTrustEnforcer *ebpf.Program `ebpf:"zero_trust_enforcer"`
		SyscallPolicyMap  *ebpf.Map     `ebpf:"syscall_policy_map"`
	}{}

	// Load the program and map into the kernel's memory
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load objects into kernel: %v", err)
	}
	// Defer cleanup so the kernel removes our program when Go exits
	defer objs.ZeroTrustEnforcer.Close()
	defer objs.SyscallPolicyMap.Close()

	// 3. Populate the eBPF Map (Our Mock Zero-Trust Policy)
	// In Phase 2, this map will be generated dynamically by angr & NVD.
	policies := map[uint32]uint32{
		56:  2, // ID 56 (clone): AUDIT (Dangerous but Needed)
		59:  1, // ID 59 (execve): ALLOW (Safe)
		101: 0, // ID 101 (ptrace): DENY (Not needed, block entirely)
	}

	log.Println("Injecting Zero-Trust Policy into Kernel Map...")
	for syscallID, action := range policies {
		if err := objs.SyscallPolicyMap.Put(syscallID, action); err != nil {
			log.Fatalf("Failed to update map for syscall %d: %v", syscallID, err)
		}
	}

	// 4. Attach the eBPF program to the sys_enter raw tracepoint
	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.ZeroTrustEnforcer,
	})
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	log.Println("✅ Shield is UP! ZeroCall-eBPF is actively enforcing the kernel.")
	log.Println("Press Ctrl+C to exit and remove the shield.")

	// 5. Keep the Go program running until the user presses Ctrl+C
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper

	log.Println("\nDetaching ZeroCall-eBPF...")
}