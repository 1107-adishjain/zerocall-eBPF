package main

// Phase 3 — Host-Aware Vulnerability Filtering (S_blocked), paper Section 4.5 / 6.11.
//
// A syscall is added to S_blocked only when a High/Critical CVE affecting it
// applies to THIS host's running kernel. We read the kernel version with
// `uname -r`, pull the NVD v2.0 feed (cached to disk, jittered backoff so a
// cloud-burst of containers never stampedes the API), and keep a CVE only when
// the host kernel falls inside its [versionStartIncluding, versionEndExcluding)
// range. This avoids the "vulnerability overblocking" of naive name scrapes:
// a bug patched on the host kernel is never blocked.

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const nvdAPIBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// A syscall-affecting CVE with the kernel range it applies to. SyscallID is the
// x86_64 number the CVE's capability maps to; this is the link the raw NVD text
// does not give us directly, so each rule names it explicitly.
type cveRule struct {
	ID             string `json:"id"`
	SyscallID      uint32 `json:"syscall_id"`
	SyscallName    string `json:"syscall_name"`
	StartIncluding string `json:"version_start_including"`
	EndExcluding   string `json:"version_end_excluding"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
}

// Seed feed: known syscall-introducing/affecting kernel CVEs with their ranges.
// Used when NVD is unreachable and as the mapping layer (NVD gives CPE ranges,
// not syscall numbers). Extend as new syscall CVEs land.
var seedCVERules = []cveRule{
	{ID: "CVE-2022-29582", SyscallID: 425, SyscallName: "io_uring_setup", StartIncluding: "5.10", EndExcluding: "5.17.3", Severity: "HIGH", Description: "io_uring use-after-free"},
	{ID: "CVE-2022-1116", SyscallID: 425, SyscallName: "io_uring_setup", StartIncluding: "5.4", EndExcluding: "5.17.0", Severity: "HIGH", Description: "io_uring integer overflow"},
	{ID: "CVE-2022-0185", SyscallID: 272, SyscallName: "unshare", StartIncluding: "5.1", EndExcluding: "5.16.2", Severity: "CRITICAL", Description: "fsconfig/unshare heap overflow -> container escape"},
	{ID: "CVE-2022-25636", SyscallID: 321, SyscallName: "bpf", StartIncluding: "5.4", EndExcluding: "5.16.10", Severity: "HIGH", Description: "netfilter bpf heap OOB write"},
	{ID: "CVE-2021-22555", SyscallID: 321, SyscallName: "bpf", StartIncluding: "2.6", EndExcluding: "5.12.0", Severity: "HIGH", Description: "netfilter OOB write -> privesc"},
	{ID: "CVE-2019-13272", SyscallID: 101, SyscallName: "ptrace", StartIncluding: "4.10", EndExcluding: "5.1.17", Severity: "HIGH", Description: "ptrace PTRACE_TRACEME privesc"},
	{ID: "CVE-2022-0492", SyscallID: 155, SyscallName: "pivot_root", StartIncluding: "2.6", EndExcluding: "5.17.0", Severity: "HIGH", Description: "cgroups v1 release_agent container escape"},
}

// nvdResponse is the slice of the NVD v2.0 JSON we consume.
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID             string          `json:"id"`
			Metrics        json.RawMessage `json:"metrics"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Criteria              string `json:"criteria"`
						VersionStartIncluding string `json:"versionStartIncluding"`
						VersionEndExcluding   string `json:"versionEndExcluding"`
						Vulnerable            bool   `json:"vulnerable"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// hostKernelVersion returns the running kernel's x.y.z, e.g. "5.15.0".
func hostKernelVersion() (string, error) {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return "", fmt.Errorf("uname -r: %w", err)
	}
	// "5.15.0-83-generic" -> "5.15.0"
	m := regexp.MustCompile(`^(\d+)\.(\d+)(?:\.(\d+))?`).FindStringSubmatch(strings.TrimSpace(string(out)))
	if m == nil {
		return "", fmt.Errorf("cannot parse kernel version %q", strings.TrimSpace(string(out)))
	}
	patch := m[3]
	if patch == "" {
		patch = "0"
	}
	return fmt.Sprintf("%s.%s.%s", m[1], m[2], patch), nil
}

// parseVer turns "5.16.2" into comparable integers. Missing parts are 0.
func parseVer(v string) [3]int {
	var out [3]int
	for i, p := range strings.SplitN(v, ".", 3) {
		if i > 2 {
			break
		}
		out[i], _ = strconv.Atoi(regexp.MustCompile(`\d+`).FindString(p))
	}
	return out
}

func cmpVer(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// inRange reports whether host is in [start, end). Empty bound = unbounded.
func inRange(host, start, end string) bool {
	h := parseVer(host)
	if start != "" && cmpVer(h, parseVer(start)) < 0 {
		return false
	}
	if end != "" && cmpVer(h, parseVer(end)) >= 0 {
		return false
	}
	return true
}

// fetchNVDFeed pulls the High/Critical kernel CVE feed, with a jittered
// exponential backoff on 429/503 and a local disk cache. Returns the raw rules
// (empty slice if the network is unavailable and no cache exists).
func fetchNVDFeed(cachePath string, online bool) ([]cveRule, error) {
	if !online {
		if rules, err := loadCache(cachePath); err == nil {
			return rules, nil
		}
		return seedCVERules, nil
	}

	url := nvdAPIBase + "?cvssV3Severity=HIGH&keywordSearch=linux+kernel+syscall&resultsPerPage=200"
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		resp, err := http.Get(url)
		if err != nil {
			lastErr = err
		} else {
			if resp.StatusCode == http.StatusOK {
				var parsed nvdResponse
				dec := json.NewDecoder(resp.Body)
				decErr := dec.Decode(&parsed)
				resp.Body.Close()
				if decErr == nil {
					rules := mergeFeed(parsed)
					_ = saveCache(cachePath, rules)
					return rules, nil
				}
				lastErr = decErr
			} else {
				resp.Body.Close()
				lastErr = fmt.Errorf("NVD returned HTTP %d", resp.StatusCode)
			}
		}
		// Jittered exponential backoff: 2^attempt seconds + up to 1s random.
		backoff := time.Duration(1<<uint(attempt))*time.Second + time.Duration(rand.Intn(1000))*time.Millisecond
		time.Sleep(backoff)
	}
	// Fall back to cache, then seed, so S_blocked is never silently empty.
	if rules, err := loadCache(cachePath); err == nil {
		return rules, nil
	}
	return seedCVERules, lastErr
}

// mergeFeed attaches NVD version ranges to our seed syscall mapping: a seed rule
// is kept, and its range is refreshed from the live NVD entry when the CVE id
// matches. CVEs with no syscall mapping are ignored (we cannot enforce them).
func mergeFeed(parsed nvdResponse) []cveRule {
	ranges := map[string][2]string{}
	for _, v := range parsed.Vulnerabilities {
		for _, cfg := range v.CVE.Configurations {
			for _, node := range cfg.Nodes {
				for _, m := range node.CPEMatch {
					if m.Vulnerable && strings.Contains(m.Criteria, "linux:linux_kernel") {
						ranges[v.CVE.ID] = [2]string{m.VersionStartIncluding, m.VersionEndExcluding}
					}
				}
			}
		}
	}
	out := make([]cveRule, 0, len(seedCVERules))
	for _, r := range seedCVERules {
		if rg, ok := ranges[r.ID]; ok {
			if rg[0] != "" {
				r.StartIncluding = rg[0]
			}
			if rg[1] != "" {
				r.EndExcluding = rg[1]
			}
		}
		out = append(out, r)
	}
	return out
}

func loadCache(path string) ([]cveRule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []cveRule
	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func saveCache(path string, rules []cveRule) error {
	b, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// computeSBlocked returns the syscall IDs to block on THIS host: every seed/feed
// CVE whose kernel range contains the host kernel. It also returns the matched
// rules so the provenance can be printed/serialised.
func computeSBlocked(cachePath string, online bool) (map[uint32]bool, []cveRule, error) {
	kernel, err := hostKernelVersion()
	if err != nil {
		return nil, nil, err
	}
	rules, ferr := fetchNVDFeed(cachePath, online) // ferr is non-fatal: we still filter on what we have
	blocked := map[uint32]bool{}
	matched := []cveRule{}
	for _, r := range rules {
		if inRange(kernel, r.StartIncluding, r.EndExcluding) {
			blocked[r.SyscallID] = true
			matched = append(matched, r)
		}
	}
	return blocked, matched, ferr
}
