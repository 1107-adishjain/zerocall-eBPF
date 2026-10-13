package main

// Phase 2 — Dynamic Workload Tracing parser (S_dynamic), paper Section 4.4.
//
// Reads a bpftrace log produced by tracer.bt and extracts the set of unique
// syscall ids the workload issued under load. bpftrace prints map entries as
// "@seen[59]: 12345" (or "SYSCALL 59" from older formats); both are accepted.
// Duplicates collapse into the set — only presence matters for S_dynamic.

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
)

// bpftrace map lines look like "@seen[59]: 420" ; also accept "SYSCALL 59".
var dynLineRE = regexp.MustCompile(`@seen\[(\d+)\]|SYSCALL\s+(\d+)`)

// parseDynamicTrace reads a bpftrace log file and returns S_dynamic.
func parseDynamicTrace(path string) (map[uint32]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[uint32]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		m := dynLineRE.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		idStr := m[1]
		if idStr == "" {
			idStr = m[2]
		}
		id, convErr := strconv.Atoi(idStr)
		if convErr != nil || id < 0 || id > 511 {
			continue
		}
		seen[uint32(id)] = true
	}
	return seen, sc.Err()
}
