package main

// Phase 4 — Policy Synthesis and Ternary Map build (Algorithm 1), paper Section 4.6.
//
// Combines the three sets into the authorised policy and the 512-slot ternary
// action map the kernel enforces:
//
//     S_req   = S_static ∪ S_dynamic
//     S_final = S_req − S_blocked        (conceptually; see the ternary map below)
//
// For every syscall id 0..511:
//     id ∈ S_req and id ∉ S_blocked  ->  1  ALLOW
//     id ∈ S_req and id ∈ S_blocked  ->  2  AUDIT / INSPECT   (conflict: inspect args)
//     otherwise                      ->  0  DENY
//
// A required capability that is also CVE-flagged is NOT silently dropped (that
// would crash the app) and NOT silently allowed (that would be a hole). It is
// routed to the in-kernel argument inspector — the AUDIT state.

import (
	"encoding/json"
	"os"
	"sort"
	"strconv"
)

const maxSyscalls = 512

// staticArtifact is what static_profiler.py writes (s_static_<binary>.json).
type staticArtifact struct {
	Count    int      `json:"count"`
	Syscalls []uint32 `json:"syscalls"`
}

// policyDoc is the serialised output of synthesis: the ternary map plus the
// provenance of every input set, so a reviewer can see how each state was derived.
type policyDoc struct {
	KernelVersion string            `json:"kernel_version"`
	SStatic       []uint32          `json:"s_static"`
	SDynamic      []uint32          `json:"s_dynamic"`
	SBlocked      []uint32          `json:"s_blocked"`
	BlockedCVEs   []cveRule         `json:"blocked_cves"`
	Map           map[string]uint32 `json:"ternary_map"` // id -> action (0/1/2)
}

func loadStatic(path string) (map[uint32]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var art staticArtifact
	if err := json.Unmarshal(b, &art); err != nil {
		return nil, err
	}
	set := map[uint32]bool{}
	for _, id := range art.Syscalls {
		set[id] = true
	}
	return set, nil
}

func sortedKeys(m map[uint32]bool) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// synthesize builds the 512-entry ternary map from the three sets (Algorithm 1).
func synthesize(sStatic, sDynamic, sBlocked map[uint32]bool) map[uint32]uint32 {
	req := map[uint32]bool{}
	for id := range sStatic {
		req[id] = true
	}
	for id := range sDynamic {
		req[id] = true
	}

	ternary := make(map[uint32]uint32, maxSyscalls)
	for id := uint32(0); id < maxSyscalls; id++ {
		switch {
		case req[id] && !sBlocked[id]:
			ternary[id] = policyAllow
		case req[id] && sBlocked[id]:
			ternary[id] = policyAudit
		default:
			ternary[id] = policyDeny
		}
	}
	return ternary
}

// writePolicyDoc serialises the synthesis result with full provenance.
func writePolicyDoc(path, kernel string, sStatic, sDynamic, sBlocked map[uint32]bool, cves []cveRule, ternary map[uint32]uint32) error {
	doc := policyDoc{
		KernelVersion: kernel,
		SStatic:       sortedKeys(sStatic),
		SDynamic:      sortedKeys(sDynamic),
		SBlocked:      sortedKeys(sBlocked),
		BlockedCVEs:   cves,
		Map:           map[string]uint32{},
	}
	for id, action := range ternary {
		// Only record non-DENY entries; DENY is the default for everything else.
		if action != policyDeny {
			doc.Map[itoa(id)] = action
		}
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func itoa(v uint32) string {
	return strconv.FormatUint(uint64(v), 10)
}
