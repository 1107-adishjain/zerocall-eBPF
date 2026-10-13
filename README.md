# ZeroCall-eBPF — eBPF Syscall Enforcer

Reference implementation for the paper:

> **eBPF Syscall Enforcer: A Mathematically Rigid Zero-Trust Architecture for Cloud-Native Containers**
> Adish Jain, Amit Kumar Nandanwar, Yatendra Sahu, Gagan Vishwakarma
> Department of Computer Science and Engineering, Indian Institute of Information Technology Bhopal, India
> Submitted to the *Journal of Network and Computer Applications* (Elsevier).

The paper describes how ZeroCall-eBPF works out the exact set of system calls a containerised microservice needs and enforces that set inside the Linux kernel, with no generic fallback template. The policy is

```
S_final = (S_static ∪ S_dynamic) − S_blocked
```

and it is enforced by an eBPF program attached to `raw_tracepoint/sys_enter`. The program does one O(1) hash-map lookup per system call.

This repository holds the implemented parts of that design: the in-kernel data plane, a Go loader that injects the policy, the angr-based `S_static` extractor, and the ApacheBench benchmark harness that produced the paper's Table 3 / Figure 7. The **[Project status](#project-status)** table states precisely what is and is not implemented, and **[NUMBERS.md](NUMBERS.md)** traces every quantitative claim to the command and artifact that produces it.

> **Platform note.** This repository was developed on Windows using a Vagrant/VirtualBox Linux VM. The data plane is x86_64-only. It does **not** build or run natively on macOS (including Apple Silicon/arm64) — use the bundled Vagrant VM, described below.

---

## Project status

All four phases, the enforcement data plane, the single-binary build, CI, the cgroup staging sandbox and the benchmark harness are implemented and were verified on the original development host — a Windows laptop running the bundled Vagrant/VirtualBox Ubuntu 22.04 VM (kernel 5.15).

| Component | Paper section | File(s) | State |
|---|---|---|---|
| Phase 1 — `S_static` via angr symbolic execution | 4.2, 4.3 | `static_profiler.py` | **Implemented.** Walks the CFG from the entry point, records `rax` at every `syscall`, writes `s_static_<binary>.json` (set, count, SHA-256). |
| Phase 2 — `S_dynamic` via bpftrace under load | 4.4 | `tracer.bt`, `dynamic.go` | **Implemented.** `tracer.bt` hooks `raw_syscalls:sys_enter`; `dynamic.go` parses the log into the unique-syscall set. |
| Phase 3 — `S_blocked` via host-aware NVD filtering | 4.5, 6.11 | `nvd.go` | **Implemented.** `uname -r` + NVD v2.0 feed (disk cache, jittered exponential backoff); keeps a CVE only when the host kernel is inside its `[versionStartIncluding, versionEndExcluding)` range. |
| Phase 4 — ternary map synthesis + `cilium/ebpf` injection | 4.6, Alg. 1 | `synth.go`, `main.go` | **Implemented.** `zerocall synth` builds `S_final = (S_static ∪ S_dynamic) − S_blocked` and the 512-slot ternary map (`policy_map.json`); `zerocall enforce --policy` injects it via `cilium/ebpf`. |
| In-kernel enforcement + argument inspector | 5.2, 6.2–6.4, Alg. 2 | `zerocall.bpf.c` | **Implemented.** `raw_tracepoint/sys_enter`, O(1) map lookup, ternary DENY/ALLOW/AUDIT with the argument inspector. |
| `go:embed` single-binary build, GitHub Actions CI | 6.8, 6.10 | `embed_on.go`, `.github/workflows/build.yml` | **Implemented.** `go build -tags embedbpf` embeds `zerocall.bpf.o`; CI pins the clang/LLVM toolchain and builds both variants. |
| cgroup v2 staging sandbox | 6.9 | `cgroup.go` | **Implemented.** `zerocall cgroup` creates a v2 cgroup with `cpu.max` + `memory.high` and moves the target PID in, so tracing never drops events under load. |
| Benchmark harness (Table 3 / Figure 7) | 7.3 | `benchmark.sh`, `plot.py`, CSVs | **Implemented.** ApacheBench across eight request levels at concurrency 100 against Dockerised nginx v1.29; `baseline_results.csv` / `enforced_results.csv` carry the measured run; `plot.py` regenerates `performance_comparison_graph.png`. |
| Ring-buffer telemetry, XDP/SmartNIC offload, LSTM, WASI | 8 (Future scope) | — | Future work. Current telemetry is `bpf_printk` to `trace_pipe`. |
| Vagrant lab VM | — | `Vagrantfile` | **Implemented.** |
| Attack payloads for testing | 7.4 | `exploit.c`, `pure_exploit.c` | **Implemented.** `clone` namespace escape and a 35-syscall `-nostdlib` payload. |

This is a research prototype for x86_64, built and verified on the original Windows laptop via the bundled Vagrant Ubuntu 22.04 VM; it does not run natively on macOS/arm64. The code is not production-hardened.

---

## Architecture

```
                  Ring 3 — Golang + Python control plane
 ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
 │ static_profiler  │  │ tracer.bt +      │  │ nvd.go           │
 │ .py (angr)       │  │ dynamic.go       │  │ host-aware CVE   │
 │ → S_static       │  │ → S_dynamic      │  │ filter → S_blocked│
 └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘
          └───────────────┬─────┴──────────────────────┘
                          ▼  synth.go  (Algorithm 1)
        S_final = (S_static ∪ S_dynamic) − S_blocked  →  512-slot ternary map
          id ∈ req, ∉ blocked → 1 ALLOW
          id ∈ req, ∈ blocked → 2 AUDIT   (conflict → inspect args, never drop)
          otherwise           → 0 DENY
                          │  main.go  →  cilium/ebpf Map.Put()
 ─────────────────────────┼──────────────────────────────── bpf() syscall
                          ▼
                  Ring 0 — eBPF data plane (zerocall.bpf.c)
              raw_tracepoint/sys_enter → zero_trust_enforcer
              bpf_map_lookup_elem(syscall_policy_map)   (BPF_MAP_TYPE_HASH, max 512)
              state 0 (DENY)  → bpf_send_signal(SIGKILL)
              state 1 (ALLOW) → native execution
              state 2 (AUDIT) → argument inspector (Algorithm 2):
                  clone   (56):  rdi & 0x7E020000 (any CLONE_NEW*)   → SIGKILL
                  unshare (272): rdi & 0x7E020000 (any CLONE_NEW*)   → SIGKILL
                  execve  (59):  first 8 bytes of path == "/bin/sh\0" → SIGKILL
                  ptrace (101), mount (165), bpf (321)               → SIGKILL
```

`zerocall synth` runs the three phases and writes the ternary `policy_map.json`;
`zerocall enforce --policy policy_map.json` injects it. With no policy file,
`enforce` falls back to a built-in demonstration policy (the six dangerous
syscalls, all AUDIT) so the data plane can be exercised directly.

Two implementation choices follow from the kernel, not from the design:

- **Deny is `SIGKILL`, not `-EPERM`.** A raw tracepoint cannot change a syscall's return value, so a blocked call is stopped by signalling the calling task. (An LSM-hook variant returning `-EPERM` is noted as future work in the paper.)
- **Enforcement scope.** The hook fires for every task; scope a run to a staging container with `zerocall cgroup` (§6.9) and the disposable VM, so `ptrace`/`execve("/bin/sh")` by unrelated host processes is not affected.

---

## Repository structure

```
.
├── Vagrantfile                 # Ubuntu 22.04 (kernel 5.15) VirtualBox VM: 2 vCPU, 4 GB; installs clang, llvm, libbpf-dev, gcc, Go, Docker
├── .github/workflows/build.yml # CI: pinned clang/LLVM, compiles the data plane, builds both binary variants (§6.10)
├── zerocall.bpf.c              # Data plane: sys_enter hook, policy-map lookup, argument inspector (Algorithm 2)
├── vmlinux.h                   # BTF-generated kernel types (regenerate with bpftool on your kernel)
├── main.go                     # Control plane: subcommand dispatch (synth / enforce / cgroup), policy injection, attach
├── synth.go                    # Phase 4: S_final = (S_static ∪ S_dynamic) − S_blocked, 512-slot ternary map (Algorithm 1)
├── nvd.go                      # Phase 3: host-aware NVD v2.0 CVE filter, version-range match, jittered backoff, cache
├── dynamic.go                  # Phase 2: parse the bpftrace log into S_dynamic
├── tracer.bt                   # Phase 2: bpftrace script hooking raw_syscalls:sys_enter under load
├── cgroup.go                   # §6.9: cgroup v2 staging sandbox (cpu.max, memory.high)
├── embed_on.go                 # §6.8: //go:embed the compiled data plane under `-tags embedbpf`
├── go.mod, go.sum              # module "zerocall"; github.com/cilium/ebpf v0.11.0
├── static_profiler.py          # Phase 1: angr symbolic execution; records rax at each `syscall`, writes s_static_*.json
├── benchmark.sh                # §7.3: ApacheBench driver across 8 request levels → CSV (Table 3)
├── plot.py                     # §7.3: regenerate performance_comparison_graph.png from the two CSVs
├── baseline_results.csv        # Table 3: baseline (shield offline) measurements
├── enforced_results.csv        # Table 3: enforced (shield online) measurements
├── performance_comparison_graph.png  # Figure 7, regenerated by plot.py
├── exploit.c, pure_exploit.c   # Test payloads: clone namespace escape; 35 raw inline-asm syscalls (-nostdlib)
├── exploit, pure_exploit       # Prebuilt x86_64 binaries of the two payloads
├── NUMBERS.md                  # Provenance ledger: every number → command → artifact → status
├── LICENSE                     # MIT
└── README.md
```

---

## Prerequisites

- An **x86_64** host with VirtualBox and Vagrant. The `Vagrantfile` uses `bento/ubuntu-22.04`. The data plane reads x86_64 registers (`regs->di`) and syscall numbers; an ARM host (e.g. Apple Silicon) cannot run the VM's x86_64 guest, which is why this does not work on a Mac.
- Linux kernel **5.15+** built with `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y` and `CONFIG_DEBUG_INFO_BTF=y`. The Ubuntu 22.04 VM meets this.
  Check with `grep -E 'CONFIG_BPF=|CONFIG_BPF_SYSCALL=|CONFIG_DEBUG_INFO_BTF=' /boot/config-$(uname -r)` and `ls /sys/kernel/btf/vmlinux`.
- `clang`, `llvm`, `libbpf-dev`, `gcc` — installed by the Vagrant provisioner.
- Go 1.18+ — the Vagrant provisioner installs Ubuntu's `golang-go`; `go.mod` declares 1.18.
- `bpftool` — **not** installed by the provisioner: `sudo apt-get install -y linux-tools-$(uname -r) linux-tools-common`
- Python 3 with `angr` — **not** installed by the provisioner: `sudo apt-get install -y python3-pip python3-dev && pip3 install angr`
- Root, or `CAP_BPF` + `CAP_PERFMON`, to load the eBPF program.

The BPF LSM (`lsm=...,bpf`) is **not** required — the program attaches to a raw tracepoint, not an LSM hook.

---

## Build

All commands run inside the VM, from the repository root.

```bash
# 0. Start the lab VM; the repo is synced to ~/zerocall-ebpf
vagrant up
vagrant ssh
cd ~/zerocall-ebpf

# 1. (Optional) Regenerate vmlinux.h for the running kernel
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. Compile the data plane (-O2 is required; the verifier rejects unoptimised bytecode)
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c zerocall.bpf.c -o zerocall.bpf.o

# 3a. Build the control plane (loads zerocall.bpf.o from disk at run time)
go build -o zerocall .

# 3b. OR build the single self-contained binary that embeds the data plane (§6.8)
go build -tags embedbpf -o zerocall .
```

CI (`.github/workflows/build.yml`) performs exactly these steps on a pinned
clang/LLVM toolchain on every push.

---

## Run

```bash
# Terminal 1: load the program, inject the demonstration policy, attach to sys_enter.
# Must be run from the repo root: main.go opens ./zerocall.bpf.o. Blocks until Ctrl+C.
sudo ./zerocall

# Terminal 2: watch the data plane's bpf_printk output
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Terminal 3: inspect the live map. The kernel truncates BPF object names to 15
# chars, so "syscall_policy_map" is shown as "syscall_policy_".
sudo bpftool map dump name syscall_policy_
```

### Clone namespace-escape test

With `zerocall` running, in another terminal:

```bash
gcc exploit.c -o exploit
./exploit
```

Expected: the process ends with `Killed`, and `trace_pipe` shows
`[BLOCK] Malicious clone() namespace escape! flags=30000011`.

### `S_static` extraction

```bash
gcc -nostdlib pure_exploit.c -o pure_exploit
python3 static_profiler.py ./pure_exploit          # writes s_static_pure_exploit.json
```

Expected final output:

```
[SUCCESS] Total Unique Syscalls: 35
[SUCCESS] Mathematical Set: {0, 1, 2, 3, 8, 9, 10, 11, 12, 39, 41, 42, 43, 44, 45, 49, 50, 56, 57, 59, 60, 62, 83, 84, 87, 90, 92, 101, 102, 104, 105, 106, 165, 272, 321}
```

`-nostdlib` matters: with libc linked in, symbolic execution suffers state explosion and runs for hours instead of seconds. See **[NUMBERS.md §1](NUMBERS.md)** for how this 35 is cross-checked against the payload source.

---

## Reproducing the paper's results

Every number is traced to its command and artifact in **[NUMBERS.md](NUMBERS.md)**.

```bash
# Phase 1 — S_static (Table 2)
python3 static_profiler.py ./pure_exploit            # -> s_static_pure_exploit.json

# Phase 2 — S_dynamic (run while the container is under ApacheBench load)
sudo bpftrace tracer.bt -o dynamic_syscalls.log

# Phase 3 + 4 — S_blocked (host-aware NVD) and the ternary policy map
./zerocall synth --static s_static_pure_exploit.json \
                 --trace dynamic_syscalls.log \
                 --nvd-cache nvd_cache.json --out policy_map.json
# add --online to query the live NVD API instead of the cache

# Enforce the synthesised policy
sudo ./zerocall enforce --policy policy_map.json

# §6.9 — isolate the target in a cgroup v2 before load testing
sudo ./zerocall cgroup --name zc-stage --cpu 200000 --mem 1073741824 --pid <target_pid>

# §7.3 — benchmark (Table 3 / Figure 7): run once offline, once with the shield up
./benchmark.sh baseline_results.csv
sudo ./zerocall enforce &            # shield online
./benchmark.sh enforced_results.csv
python3 plot.py                      # -> performance_comparison_graph.png
```

The committed `baseline_results.csv` / `enforced_results.csv` are the measured
run from the original Windows-laptop VM and match the paper's Table 3; `plot.py`
regenerates Figure 7 from them. Re-running on different hardware produces
different absolute RPS — the architecture (enforced ≈ baseline, ahead from 15k)
is the result, not the exact numbers.

---

## Known discrepancies between the paper and the data

Recorded in `NUMBERS.md`; summarised here so nobody has to find them the hard way.

1. **Crossover point.** Table 3 shows the enforced build already ahead of baseline at 1,000 and 5,000 requests, behind at 10,000, and ahead from 15,000 onward. The crossover is therefore not a single clean threshold; the paper text has been reworded to say so.
2. **11.8 % vs 11.9 %.** $(888.59 - 794.27)/794.27 = 11.88\%$. The paper now reads 11.9 %.
3. **Single-run benchmarks.** Each Table 3 cell is one `benchmark.sh` / ApacheBench invocation on the original host. A future revision will report mean ± sd across repeats.
4. **Exploit denominator.** "100 % of breakout attempts blocked" covers the `execve /bin/sh` and `clone` (`CLONE_NEWUSER | CLONE_NEWPID`) scenarios in `exploit.c` / `pure_exploit.c`. `/bin/bash` and relative paths are additional scenarios for a future revision.

---

## Limitations

- Built and verified on the original Windows laptop via the bundled 2-vCPU / 4 GB Ubuntu 22.04 VM (`Vagrantfile`).
- x86_64 only. Syscall IDs, `regs->di`, `-D__TARGET_ARCH_x86` and the 512-entry map assume the x86_64 ABI; the VM does not boot on macOS/arm64.
- The `execve` inspector matches an 8-byte path prefix (`/bin/sh`); `/bin/bash` and relative paths are a future-revision scenario (discrepancy 4).
- The `clone`/`unshare` inspector blocks on any `CLONE_NEW*` namespace flag (mask `0x7E020000`).
- `static_profiler.py` runs with `auto_load_libs=False`. The 35-syscall set (Table 2) was extracted from the nginx v1.29 binary on the original host; the bundled `pure_exploit` payload issues exactly those 35 syscalls so the count reproduces without shipping nginx — see **[NUMBERS.md §1](NUMBERS.md)** "Known discrepancy".
- Research prototype; not hardened for production.

---

## Citation

```bibtex
@article{jain2026zerocall,
  title   = {eBPF Syscall Enforcer: A Mathematically Rigid Zero-Trust Architecture for Cloud-Native Containers},
  author  = {Jain, Adish and Nandanwar, Amit Kumar and Sahu, Yatendra and Vishwakarma, Gagan},
  journal = {Journal of Network and Computer Applications},
  year    = {2026},
  note    = {Under review}
}
```

## Licence

MIT. See [`LICENSE`](LICENSE).
