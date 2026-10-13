package main

// cgroup v2 staging sandbox (paper Section 6.9).
//
// Before dynamic tracing, the target is pinned into a dedicated cgroup v2 with a
// cpu.max quota and a memory.high ceiling, so the benchmark saturates the
// CONTAINER's limits, not the host's. Without this, a 500k-thread ApacheBench run
// starves the kernel tracepoint and drops events, leaving S_dynamic incomplete.
//
// Usage:
//   zerocall cgroup --name zc-stage --cpu 200000 --mem 1073741824 --pid <pid>
// (cpu is max microseconds per 100ms period; mem is bytes.)

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
)

const cgroupRoot = "/sys/fs/cgroup"

func init() { cgroupDispatch = runCgroup }

// runCgroup creates an isolated cgroup v2 and (optionally) moves a PID into it.
func runCgroup(args []string) {
	fs := flag.NewFlagSet("cgroup", flag.ExitOnError)
	name := fs.String("name", "zc-stage", "cgroup name under "+cgroupRoot)
	cpuMax := fs.Int("cpu", 200000, "cpu.max quota (microseconds per 100ms period)")
	memHigh := fs.Int64("mem", 1<<30, "memory.high ceiling in bytes")
	pid := fs.Int("pid", 0, "PID to move into the cgroup (0 = just create it)")
	_ = fs.Parse(args)

	if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err != nil {
		log.Fatalf("cgroup v2 not mounted at %s: %v", cgroupRoot, err)
	}

	dir := filepath.Join(cgroupRoot, *name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatalf("create cgroup %s: %v", dir, err)
	}

	// cpu.max is written as "<quota> <period>"; period is fixed at 100000us.
	writeCgroupFile(dir, "cpu.max", fmt.Sprintf("%d 100000", *cpuMax))
	writeCgroupFile(dir, "memory.high", strconv.FormatInt(*memHigh, 10))

	if *pid > 0 {
		writeCgroupFile(dir, "cgroup.procs", strconv.Itoa(*pid))
		log.Printf("moved PID %d into %s", *pid, dir)
	}
	log.Printf("staging cgroup ready: %s (cpu.max=%d/100000us, memory.high=%d bytes)", dir, *cpuMax, *memHigh)
}

func writeCgroupFile(dir, file, val string) {
	path := filepath.Join(dir, file)
	if err := os.WriteFile(path, []byte(val), 0o644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
}
