package main

// ZeroCall-eBPF control plane (Ring 3).
//
// Subcommands:
//   zerocall synth    — run Phases 1–4 (S_static ∪ S_dynamic) − S_blocked and
//                       write policy_map.json (Algorithm 1). No kernel changes.
//   zerocall enforce  — load the embedded data plane, inject the policy, and
//                       attach to raw_tracepoint/sys_enter (Algorithm 2).
//
// With no subcommand it runs `enforce` with the built-in demonstration policy,
// preserving the original single-command behaviour.

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Ternary action states, shared by synth.go and the kernel map (zerocall.bpf.c).
const (
	policyDeny  uint32 = 0
	policyAllow uint32 = 1
	policyAudit uint32 = 2
)

// bpfObject holds the compiled data plane. It is populated at compile time only
// under `-tags embedbpf` (embed_on.go, the single-binary CI build, paper §6.8);
// a plain `go build` leaves it nil and enforce() loads zerocall.bpf.o from disk.
var bpfObject []byte

// cgroupDispatch is wired up by cgroup.go's init() so the cgroup subcommand
// stays in its own file.
var cgroupDispatch func([]string)

// Demonstration policy: the six dangerous syscalls, all routed to the argument
// inspector. Used by `enforce` when no synthesised policy_map.json is supplied.
var demoPolicy = map[uint32]uint32{
	56:  policyAudit, // clone
	59:  policyAudit, // execve
	101: policyAudit, // ptrace
	165: policyAudit, // mount
	272: policyAudit, // unshare
	321: policyAudit, // bpf
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "synth":
			runSynth(os.Args[2:])
			return
		case "enforce":
			runEnforce(os.Args[2:])
			return
		case "cgroup":
			cgroupDispatch(os.Args[2:])
			return
		}
	}
	runEnforce(nil) // backward-compatible default
}

// runSynth executes Phases 1–4 and writes the ternary policy map to disk.
func runSynth(args []string) {
	fs := flag.NewFlagSet("synth", flag.ExitOnError)
	staticPath := fs.String("static", "", "S_static artifact from static_profiler.py (s_static_<binary>.json)")
	tracePath := fs.String("trace", "", "S_dynamic bpftrace log from tracer.bt")
	nvdCache := fs.String("nvd-cache", "nvd_cache.json", "NVD feed cache path")
	nvdOnline := fs.Bool("online", false, "query the live NVD API (default: use cache/seed)")
	out := fs.String("out", "policy_map.json", "output ternary policy map")
	_ = fs.Parse(args)

	sStatic := map[uint32]bool{}
	if *staticPath != "" {
		s, err := loadStatic(*staticPath)
		if err != nil {
			log.Fatalf("load S_static: %v", err)
		}
		sStatic = s
	}
	sDynamic := map[uint32]bool{}
	if *tracePath != "" {
		d, err := parseDynamicTrace(*tracePath)
		if err != nil {
			log.Fatalf("parse S_dynamic: %v", err)
		}
		sDynamic = d
	}
	sBlocked, cves, ferr := computeSBlocked(*nvdCache, *nvdOnline)
	if ferr != nil {
		log.Printf("[warn] NVD feed degraded (%v); filtering on cache/seed", ferr)
	}
	kernel, _ := hostKernelVersion()

	ternary := synthesize(sStatic, sDynamic, sBlocked)
	if err := writePolicyDoc(*out, kernel, sStatic, sDynamic, sBlocked, cves, ternary); err != nil {
		log.Fatalf("write policy: %v", err)
	}

	allow, audit := 0, 0
	for _, a := range ternary {
		switch a {
		case policyAllow:
			allow++
		case policyAudit:
			audit++
		}
	}
	fmt.Printf("S_static=%d  S_dynamic=%d  S_blocked=%d  ->  ALLOW=%d  AUDIT=%d  DENY=%d\n",
		len(sStatic), len(sDynamic), len(sBlocked), allow, audit, maxSyscalls-allow-audit)
	fmt.Printf("policy written to %s\n", *out)
}

// loadPolicyMap reads a synthesised policy_map.json back into id->action.
func loadPolicyMap(path string) (map[uint32]uint32, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc policyDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	m := map[uint32]uint32{}
	for k, v := range doc.Map {
		id, convErr := strconv.ParseUint(k, 10, 32)
		if convErr != nil {
			continue
		}
		m[uint32(id)] = v
	}
	return m, nil
}

// runEnforce loads the embedded data plane, injects the policy, and attaches.
func runEnforce(args []string) {
	fs := flag.NewFlagSet("enforce", flag.ExitOnError)
	policyPath := fs.String("policy", "", "synthesised policy_map.json (default: built-in demo policy)")
	_ = fs.Parse(args)

	log.Println("Starting ZeroCall-eBPF Control Plane...")

	// Load the embedded object; fall back to the on-disk file if the embed is
	// empty (e.g. built before zerocall.bpf.o existed).
	var spec *ebpf.CollectionSpec
	var err error
	if len(bpfObject) > 0 {
		spec, err = ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	} else {
		spec, err = ebpf.LoadCollectionSpec("zerocall.bpf.o")
	}
	if err != nil {
		log.Fatalf("Failed to load eBPF object: %v", err)
	}

	objs := struct {
		ZeroTrustEnforcer *ebpf.Program `ebpf:"zero_trust_enforcer"`
		SyscallPolicyMap  *ebpf.Map     `ebpf:"syscall_policy_map"`
	}{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load objects into kernel: %v", err)
	}
	defer objs.ZeroTrustEnforcer.Close()
	defer objs.SyscallPolicyMap.Close()

	policy := demoPolicy
	if *policyPath != "" {
		p, perr := loadPolicyMap(*policyPath)
		if perr != nil {
			log.Fatalf("load policy %s: %v", *policyPath, perr)
		}
		policy = p
		log.Printf("Loaded synthesised policy from %s", *policyPath)
	} else {
		log.Println("Using built-in demonstration policy (run `zerocall synth` for a synthesised one)")
	}

	log.Printf("Injecting zero-trust policy (%d entries) into kernel map...", len(policy))
	for syscallID, action := range policy {
		if err := objs.SyscallPolicyMap.Put(syscallID, action); err != nil {
			log.Fatalf("Failed to update map for syscall %d: %v", syscallID, err)
		}
	}

	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.ZeroTrustEnforcer,
	})
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	log.Println("Shield is UP. ZeroCall-eBPF is enforcing. Press Ctrl+C to exit.")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
	log.Println("Detaching ZeroCall-eBPF...")
}
